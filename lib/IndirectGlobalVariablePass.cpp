//===----------------------------------------------------------------------===//
// ArmorComp — IndirectGlobalVariablePass (Indirect Global Variable Access)
//
// For each direct GlobalVariable operand inside an annotated function,
// inserts a volatile load of a proxy pointer global before that instruction
// and replaces the original GV operand with the loaded pointer.
//
// This breaks the static cross-reference (xref) graph that IDA/Ghidra build
// by scanning instruction operands for global addresses.
//
// Example:
//   Before:  %x = load i32, ptr @g_counter
//   After:   %igv.ptr = load volatile ptr, ptr @__armorcomp_igv_g_counter
//            %x = load i32, ptr %igv.ptr
//
// The proxy global:
//   @__armorcomp_igv_g_counter = weak ptr @g_counter
//
// Skips:
//   - PHI nodes  (insertion point = predecessor block, too complex)
//   - ConstantExpr operands (cannot replace constants with instruction values)
//   - Function globals (handled by IndirectCallPass)
//   - "llvm.*" globals (LLVM intrinsic infrastructure)
//   - "__armorcomp_*" globals (ArmorComp's own globals — avoid recursion)
//===----------------------------------------------------------------------===//

#include "ArmorComp/IndirectGlobalVariablePass.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasIGVAnnotation(Function &F) {
  Module *M = F.getParent();
  GlobalVariable *GV = M->getGlobalVariable("llvm.global.annotations");
  if (!GV || !GV->hasInitializer()) return false;

  auto *arr = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!arr) return false;

  for (unsigned i = 0, e = arr->getNumOperands(); i < e; ++i) {
    auto *cs = dyn_cast<ConstantStruct>(arr->getOperand(i));
    if (!cs || cs->getNumOperands() < 2) continue;
    if (cs->getOperand(0)->stripPointerCasts() != &F) continue;

    auto *strGV =
        dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
    if (!strGV || !strGV->hasInitializer()) continue;

    auto *strData = dyn_cast<ConstantDataArray>(strGV->getInitializer());
    if (!strData) continue;

    if (strData->getAsCString() == "igv") return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Returns true for GVs that must NOT be proxied.
static bool shouldSkipGV(const GlobalVariable *GV) {
  StringRef name = GV->getName();
  // LLVM intrinsic infrastructure (metadata, ctors, annotations, etc.)
  if (name.starts_with("llvm.")) return true;
  // ArmorComp's own globals — avoid infinite proxy chains
  if (name.starts_with("__armorcomp_")) return true;
  // Annotation-string storage (created by clang for annotate("..."))
  // These are ConstantDataArrays; proxying them would corrupt annotation
  // scanning done by all other passes.  Their names typically start with
  // ".str" but we rely on the type check instead: only proxy GVs that are
  // actually used as POINTER operands, not as constant initializer data.
  return false;
}

// Get or create the proxy pointer global for a given GV.
//   @__armorcomp_igv_{name} = weak ptr @gv
static GlobalVariable *getOrCreateProxy(Module &M, GlobalVariable *GV) {
  std::string proxyName = ("__armorcomp_igv_" + GV->getName()).str();

  if (auto *existing = M.getNamedGlobal(proxyName))
    return existing;

  // Create a mutable (non-constant) pointer global initialised to the address
  // of the original GV.  WeakAnyLinkage ensures one definition across TUs.
  PointerType *PtrTy = PointerType::get(M.getContext(), /*AS=*/0);
  auto *ProxyGV = new GlobalVariable(
      M, PtrTy, /*isConstant=*/false,
      GlobalValue::WeakAnyLinkage,
      GV,        // initializer = &original_gv
      proxyName);
  ProxyGV->setAlignment(Align(8));
  return ProxyGV;
}

// ─────────────────────────────────────────────────────────────────────────────
// IndirectGlobalVariablePass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses
IndirectGlobalVariablePass::run(Function &F,
                                FunctionAnalysisManager & /*AM*/) {
  bool shouldIGV = !annotateOnly || hasIGVAnnotation(F)
                   || armorcomp::configSaysApply(F.getName(), "igv");
  if (!shouldIGV) return PreservedAnalyses::all();

  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();

  Module *M = F.getParent();

  // ── Phase 1: collect all (Instruction, GlobalVariable) pairs ─────────────
  //
  // We snapshot before modifying to avoid iterator invalidation.
  // For each instruction, we collect each UNIQUE GV it references directly
  // as an operand (not inside ConstantExpr, not in PHI nodes).

  struct Replacement {
    Instruction    *I;
    GlobalVariable *GV;
  };
  std::vector<Replacement> replacements;

  for (auto &BB : F) {
    for (auto &I : BB) {
      // PHI nodes: the correct insertion point would be in a predecessor
      // basic block, which requires knowing which predecessor the value
      // comes from.  Skip for safety.
      if (isa<PHINode>(&I)) continue;

      SmallPtrSet<GlobalVariable *, 4> seenInInstr;

      for (Use &Op : I.operands()) {
        Value *V = Op.get();

        // Skip ConstantExpr wrappers — we cannot insert a load inside
        // a constant expression.
        if (isa<ConstantExpr>(V)) continue;

        auto *GV = dyn_cast<GlobalVariable>(V);
        if (!GV) continue;

        // Skip functions — IndirectCallPass handles those.
        // (GlobalVariable is never a Function, but guard explicitly.)
        if (isa<Function>(GV)) continue;

        if (shouldSkipGV(GV)) continue;

        // Deduplicate per instruction: one proxy load per (I, GV) pair
        // handles multiple operand slots that hold the same GV.
        if (!seenInInstr.insert(GV).second) continue;

        replacements.push_back({&I, GV});
      }
    }
  }

  if (replacements.empty()) return PreservedAnalyses::all();

  // ── Phase 2: insert proxy loads and replace operands ─────────────────────

  SmallPtrSet<GlobalVariable *, 16> proxiedGVs;

  for (auto &[I, GV] : replacements) {
    GlobalVariable *ProxyGV = getOrCreateProxy(*M, GV);

    // Insert volatile load of the proxy pointer BEFORE the using instruction.
    IRBuilder<> IRB(I);
    Value *Ptr = IRB.CreateLoad(IRB.getPtrTy(), ProxyGV,
                                /*isVolatile=*/true, "igv.ptr");

    // Replace every operand of I that equals GV with the loaded Ptr.
    // replaceUsesOfWith handles the case where GV appears in multiple
    // operand slots of the same instruction.
    I->replaceUsesOfWith(GV, Ptr);

    proxiedGVs.insert(GV);
  }

  errs() << "[ArmorComp][IGV] indirected: " << F.getName()
         << " (" << replacements.size() << " access"
         << (replacements.size() > 1 ? "es" : "") << ", "
         << proxiedGVs.size() << " global"
         << (proxiedGVs.size() > 1 ? "s" : "") << ")\n";

  return PreservedAnalyses::none();
}
