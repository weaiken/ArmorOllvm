//===----------------------------------------------------------------------===//
// ArmorComp — VMPPass (VMP — Virtual Machine Protection)
//
// Annotation: __attribute__((annotate("vmp")))
// Applies VMPLifter + VMPCodeGen to each targeted function.
// See include/ArmorComp/VMPPass.h for design documentation.
//===----------------------------------------------------------------------===//

#include "ArmorComp/VMPPass.h"
#include "ArmorComp/VMPCodeGen.h"
#include "ArmorComp/VMPLifter.h"
#include "ArmorComp/VMPOpcodes.h"
#include "ArmorComp/ObfuscationConfig.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// ─────────────────────────────────────────────────────────────────────────────
// Annotation detection
// ─────────────────────────────────────────────────────────────────────────────

static bool hasVMPAnnotation(Function &F) {
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

        if (strData->getAsCString() == "vmp") return true;
      }
    }
  }

check_config:
  return armorcomp::configSaysApply(F.getName(), "vmp");
}

// ─────────────────────────────────────────────────────────────────────────────
// VMPPass::run
// ─────────────────────────────────────────────────────────────────────────────

PreservedAnalyses VMPPass::run(Function &F, FunctionAnalysisManager & /*AM*/) {
  // Skip declarations and empty functions.
  if (F.isDeclaration() || F.empty()) return PreservedAnalyses::all();

  // Skip ArmorComp's own generated functions (dispatcher stubs, etc.)
  if (F.getName().startswith("__armorcomp_"))
    return PreservedAnalyses::all();

  // Check annotation / config
  bool shouldVirt = !annotateOnly
                    || hasVMPAnnotation(F)
                    || armorcomp::configSaysApply(F.getName(), "vmp");
  if (!shouldVirt) return PreservedAnalyses::all();

  // ── Lift LLVM IR → VMP bytecode ──────────────────────────────────────────
  armorcomp::vmp::VMPLifter lifter;
  auto bcOpt = lifter.lift(F);

  if (!bcOpt.has_value()) {
    errs() << "[ArmorComp][VMP] skipped (unsupported IR): " << F.getName()
           << "\n";
    return PreservedAnalyses::all();
  }

  // Make a mutable copy — we will scramble then encrypt in-place.
  std::vector<uint8_t> bc = *bcOpt;
  unsigned virtInstrs = lifter.virtualInstrCount();

  // ── Per-function opcode scramble + XTEA encryption ──────────────────────
  std::string fnName = F.getName().str();

  // 1. Optional disassembly output (before scramble, so opcodes are semantic).
  if (getenv("ARMORCOMP_VMP_DISASM")) {
    std::string disasm;
    armorcomp::vmp::disassembleBytecode(bc, disasm);
    errs() << "[VMP] Disassembly of " << F.getName() << ":\n" << disasm;
  }

  // 2. Opcode randomisation: semantic byte → physical byte (Fisher-Yates on
  //    a permutation seeded by fnvHash(fnName + "_vmp_opmap")).
  armorcomp::vmp::OpcodeMap opcodeMap = armorcomp::vmp::genOpcodeMap(fnName);
  armorcomp::vmp::scrambleBytecode(bc, opcodeMap);

  // 3. Bytecode integrity hash (FNV-1a over scrambled, pre-encryption bytes).
  //    The dispatcher re-computes this after decryption and traps on mismatch.
  uint64_t bcHash = armorcomp::vmp::hashBytecode(bc);

  // 4. XTEA-CTR encryption: replaces 8-byte XOR with 32-round XTEA cipher.
  armorcomp::vmp::XTEAKey xteaKey = armorcomp::vmp::genXTEAKey(fnName);
  armorcomp::vmp::encryptBytecodeXTEA(bc, xteaKey);

  // ── Inject bytecode + generate dispatcher ────────────────────────────────
  Module *M = F.getParent();
  armorcomp::vmp::VMPCodeGen codegen(*M);

  if (!codegen.virtualize(F, bc, lifter.getGVTable(), lifter.getCallTable(),
                           xteaKey, opcodeMap, bcHash)) {
    errs() << "[ArmorComp][VMP] codegen failed: " << F.getName() << "\n";
    return PreservedAnalyses::all();
  }

  errs() << "[ArmorComp][VMP] virtualized: " << F.getName()
         << " (" << bc.size() << " bytecode bytes, "
         << virtInstrs << " virtual instrs)\n";

  return PreservedAnalyses::none();
}
