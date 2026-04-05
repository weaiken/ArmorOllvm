//===----------------------------------------------------------------------===//
// ArmorComp — SwitchObfPass (Switch Statement Obfuscation)
//
// Replaces every SwitchInst in a targeted function with a dense jump-table
// lookup + indirectbr + volatile-zero XOR, defeating IDA Pro's switch pattern
// matcher.  See include/ArmorComp/SwitchObfPass.h for full design documentation.
//===----------------------------------------------------------------------===//

#include "ArmorComp/SwitchObfPass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasSwitchAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *annGV = M->getGlobalVariable("llvm.global.annotations");
  if (!annGV || !annGV->hasInitializer()) goto check_config;

  {
    auto *arr = dyn_cast<ConstantArray>(annGV->getInitializer());
    if (arr) {
      for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
        auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
        if (!cs || cs->getNumOperands() < 2) continue;

        auto *fn = dyn_cast<Function>(cs->getOperand(0)->stripPointerCasts());
        if (fn != &F) continue;

        auto *strGV =
            dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strGV || !strGV->hasInitializer()) continue;

        auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
        if (!strData) continue;

        if (strData->getAsCString() == "sob") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "sob");
}

// ─────────────────────────────────────────────────────────────────────────────
// Get or create the shared volatile-zero global for SOB.
// Separate from __armorcomp_rvo_zero so the two globals remain independent;
// IDA cannot trivially alias them.
// ─────────────────────────────────────────────────────────────────────────────

static GlobalVariable *getOrCreateSobZero(Module &M, Type *I64Ty) {
  const StringRef name = "__armorcomp_sob_zero";
  if (auto *G = M.getGlobalVariable(name)) return G;

  auto *G = new GlobalVariable(
      M, I64Ty, /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      ConstantInt::get(I64Ty, 0),
      name);
  G->setAlignment(Align(8));
  return G;
}

// ─────────────────────────────────────────────────────────────────────────────
// Transform one SwitchInst → indirectbr via dense jump table.
// Returns true on success.  Caller must not hold iterators into the function
// across this call.
// ─────────────────────────────────────────────────────────────────────────────

static bool obfuscateSwitch(SwitchInst *SI, GlobalVariable *SobZero,
                             unsigned &tableCounter) {
  Function *F  = SI->getParent()->getParent();
  Module   *M  = F->getParent();
  LLVMContext &Ctx = M->getContext();

  // Skip if any successor is the entry block (blockaddress() cannot be taken
  // for the function entry block).
  BasicBlock *EntryBB = &F->getEntryBlock();
  for (unsigned i = 0; i < SI->getNumSuccessors(); ++i)
    if (SI->getSuccessor(i) == EntryBB)
      return false;

  // Require at least one case — a switch with only a default is trivial.
  unsigned numCases = SI->getNumCases();
  if (numCases == 0) return false;

  // The switch condition must be an integer type.
  Value *Cond = SI->getCondition();
  auto *SwitchIntTy = dyn_cast<IntegerType>(Cond->getType());
  if (!SwitchIntTy) return false;

  // ── Gather case → BB map and compute range ────────────────────────────────
  // Use signed int64 for range arithmetic (case values can be negative).
  std::map<int64_t, BasicBlock *> caseMap;
  int64_t minCase = INT64_MAX;
  int64_t maxCase = INT64_MIN;

  for (auto &Case : SI->cases()) {
    int64_t cv = Case.getCaseValue()->getSExtValue();
    caseMap[cv]  = Case.getCaseSuccessor();
    if (cv < minCase) minCase = cv;
    if (cv > maxCase) maxCase = cv;
  }

  int64_t range = maxCase - minCase;
  // Sparsity guard: skip if the range exceeds 1023 (table would be wasteful).
  if (range < 0 || range > 1023) return false;

  BasicBlock *DefaultBB = SI->getDefaultDest();

  // ── Build the dense jump table ────────────────────────────────────────────
  // Layout:
  //   entries [0 .. range]   → case dest (or default if no case at that value)
  //   entry  [range+1]       → default dest (out-of-range clamping target)
  uint64_t tableSize = (uint64_t)range + 2;

  Type *PtrTy = PointerType::getUnqual(Ctx);   // opaque ptr (LLVM 17+)
  Type *I64Ty = Type::getInt64Ty(Ctx);

  std::vector<Constant *> TableEntries;
  TableEntries.reserve(tableSize);

  for (uint64_t i = 0; i + 1 < tableSize; ++i) {
    int64_t cv = minCase + (int64_t)i;
    auto it = caseMap.find(cv);
    BasicBlock *BB = (it != caseMap.end()) ? it->second : DefaultBB;
    TableEntries.push_back(BlockAddress::get(F, BB));
  }
  // Default slot at index [range+1]
  TableEntries.push_back(BlockAddress::get(F, DefaultBB));

  ArrayType *TableTy  = ArrayType::get(PtrTy, tableSize);
  Constant  *TableInit = ConstantArray::get(TableTy, TableEntries);

  GlobalVariable *TableGV = new GlobalVariable(
      *M, TableTy, /*isConstant=*/true,
      GlobalValue::PrivateLinkage, TableInit,
      "sob_table_" + std::to_string(tableCounter++));
  TableGV->setAlignment(Align(8));

  // ── Inject IR before the SwitchInst ───────────────────────────────────────
  IRBuilder<> IRB(SI);

  // Step 1: Normalise condition to 0-based index.
  //   %sob.idx.raw = sub <SwitchTy> %cond, <minCase>
  Constant *MinCaseConst = ConstantInt::get(SwitchIntTy, (uint64_t)minCase,
                                            /*isSigned=*/true);
  Value *IdxRaw = IRB.CreateSub(Cond, MinCaseConst, "sob.idx.raw");

  // Step 2: Bounds check — unsigned compare handles the wrap-around case when
  //   Cond < minCase (the sub produces a large unsigned value).
  //   %sob.inrange = icmp ule <SwitchTy> %sob.idx.raw, <range>
  Constant *RangeConst = ConstantInt::get(SwitchIntTy, (uint64_t)range);
  Value *InRange = IRB.CreateICmpULE(IdxRaw, RangeConst, "sob.inrange");

  // Step 3: Clamp out-of-range to default slot.
  //   %sob.idx = select i1 %sob.inrange, %sob.idx.raw, <defaultSlot>
  Constant *DefaultSlotConst = ConstantInt::get(SwitchIntTy, tableSize - 1);
  Value *Idx = IRB.CreateSelect(InRange, IdxRaw, DefaultSlotConst, "sob.idx");

  // Step 4: Widen to i64 for GEP (sext preserves sign for signed indices;
  //   after clamping the value is always in [0, tableSize-1] so zext/sext
  //   are equivalent — using sext matches the header documentation).
  Value *Idx64 = IRB.CreateIntCast(Idx, I64Ty, /*isSigned=*/true, "sob.idx64");

  // Step 5: GEP into the table.
  //   %sob.gep = getelementptr [N x ptr], @sob_table_N, i64 0, i64 %sob.idx64
  Value *Zero64 = ConstantInt::get(I64Ty, 0);
  Value *GEP = IRB.CreateInBoundsGEP(TableTy, TableGV,
                                      {Zero64, Idx64}, "sob.gep");

  // Step 6: Volatile load of the table entry.
  //   %sob.raw_ptr = load volatile ptr, %sob.gep
  Value *RawPtr = IRB.CreateLoad(PtrTy, GEP, /*isVolatile=*/true,
                                  "sob.raw_ptr");

  // Step 7: Volatile load of the XOR mask (always 0 at runtime).
  //   %sob.zero = load volatile i64, @__armorcomp_sob_zero
  Value *Zero = IRB.CreateLoad(I64Ty, SobZero, /*isVolatile=*/true,
                                "sob.zero");

  // Steps 8-10: ptrtoint → XOR → inttoptr  (the IDA-defeating sequence).
  //   %sob.tgt_int = ptrtoint ptr %sob.raw_ptr to i64
  //   %sob.xor_int = xor i64 %sob.tgt_int, %sob.zero
  //   %sob.target  = inttoptr i64 %sob.xor_int to ptr
  Value *TgtInt = IRB.CreatePtrToInt(RawPtr, I64Ty, "sob.tgt_int");
  Value *XorInt = IRB.CreateXor(TgtInt, Zero,       "sob.xor_int");
  Value *Target = IRB.CreateIntToPtr(XorInt, PtrTy,  "sob.target");

  // Step 11: Create indirectbr with all unique successor BBs as possible
  //   destinations (required by LLVM verifier — indirectbr must list all
  //   reachable targets).
  SmallPtrSet<BasicBlock *, 8> DestSet;
  DestSet.insert(DefaultBB);
  for (auto &Case : SI->cases())
    DestSet.insert(Case.getCaseSuccessor());

  IndirectBrInst *IBI = IndirectBrInst::Create(Target, DestSet.size(), SI);
  for (BasicBlock *BB : DestSet)
    IBI->addDestination(BB);

  // Step 12: Remove the original SwitchInst.
  SI->eraseFromParent();

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// SwitchObfPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses SwitchObfPass::run(Function &F,
                                      FunctionAnalysisManager & /*AM*/) {
  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();
  if (F.getName().startswith("__armorcomp_")) return PreservedAnalyses::all();
  // Exception-handling functions have complex control flow — skip.
  if (F.hasPersonalityFn()) return PreservedAnalyses::all();

  bool shouldObf = !annotateOnly
                   || hasSwitchAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "sob");
  if (!shouldObf) return PreservedAnalyses::all();

  Module    *M    = F.getParent();
  LLVMContext &Ctx = M->getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  GlobalVariable *SobZero = getOrCreateSobZero(*M, I64Ty);

  // Snapshot all SwitchInsts before any modification (eraseFromParent
  // invalidates iterators).
  std::vector<SwitchInst *> switches;
  for (auto &BB : F)
    if (auto *SI = dyn_cast<SwitchInst>(BB.getTerminator()))
      switches.push_back(SI);

  if (switches.empty()) return PreservedAnalyses::all();

  // Per-function table name counter (unique within the module is sufficient
  // because all tables use PrivateLinkage).
  static unsigned tableCounter = 0;

  unsigned count = 0;
  for (SwitchInst *SI : switches)
    if (obfuscateSwitch(SI, SobZero, tableCounter))
      ++count;

  if (count == 0) return PreservedAnalyses::all();

  errs() << "[ArmorComp][SOB] obfuscated: " << F.getName()
         << " (" << count << " switch" << (count > 1 ? "es" : "") << ")\n";

  return PreservedAnalyses::none();
}
