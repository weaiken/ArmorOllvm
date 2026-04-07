//===----------------------------------------------------------------------===//
// ArmorComp — Plugin entry point  (v0.26.0)
//
// All passes registered via a single llvmGetPassPluginInfo() entry point.
//
// Registered passes
// ─────────────────
//   armorcomp-hello        : HelloPass                — diagnostic (prints fn names)
//   armorcomp-strenc       : StrEncPass               — string encryption (module, annotation mode)
//   armorcomp-strenc-all   : StrEncPass               — string encryption (all strings)
//   armorcomp-genc         : GlobalEncPass            — integer global encryption (module, annotation mode)
//   armorcomp-genc-all     : GlobalEncPass            — integer global encryption (all eligible globals)
//   armorcomp-split        : SplitPass                — basic block splitting (annotation mode)
//   armorcomp-split-all    : SplitPass                — basic block splitting (all functions)
//   armorcomp-sub          : SubPass                  — instruction substitution (annotation mode)
//   armorcomp-sub-all      : SubPass                  — instruction substitution (all functions)
//   armorcomp-mba          : MBAPass                  — mixed boolean-arithmetic (annotation mode)
//   armorcomp-mba-all      : MBAPass                  — mixed boolean-arithmetic (all functions)
//   armorcomp-cob          : ConditionObfPass         — comparison obfuscation (annotation mode)
//   armorcomp-cob-all      : ConditionObfPass         — comparison obfuscation (all functions)
//   armorcomp-bcf          : BCFPass                  — bogus control flow (annotation mode)
//   armorcomp-bcf-all      : BCFPass                  — bogus control flow (all functions)
//   armorcomp-op           : OpaquePredicatePass       — opaque predicate insertion (annotation mode)
//   armorcomp-op-all       : OpaquePredicatePass       — opaque predicate insertion (all functions)
//   armorcomp-cff          : CFFPass                  — CFG flattening (annotation mode)
//   armorcomp-cff-all      : CFFPass                  — CFG flattening (all functions)
//   armorcomp-icall        : IndirectCallPass         — indirect call obfuscation (annotation mode)
//   armorcomp-icall-all    : IndirectCallPass         — indirect call obfuscation (all functions)
//   armorcomp-ibr          : IndirectBranchPass       — indirect branch obfuscation (annotation mode)
//   armorcomp-ibr-all      : IndirectBranchPass       — indirect branch obfuscation (all functions)
//   armorcomp-igv          : IndirectGlobalVariablePass — indirect GV access (annotation mode)
//   armorcomp-igv-all      : IndirectGlobalVariablePass — indirect GV access (all functions)
//   armorcomp-spo          : SPOPass                  — stack pointer obfuscation (annotation mode)
//   armorcomp-spo-all      : SPOPass                  — stack pointer obfuscation (all functions)
//   armorcomp-co           : ConstObfPass             — integer constant obfuscation (annotation mode)
//   armorcomp-co-all       : ConstObfPass             — integer constant obfuscation (all functions)
//   armorcomp-outline      : OutlinePass              — basic block outlining (annotation mode)
//   armorcomp-outline-all  : OutlinePass              — basic block outlining (all functions)
//   armorcomp-df           : FlattenDataFlowPass      — stack variable pool merge (annotation mode)
//   armorcomp-df-all       : FlattenDataFlowPass      — stack variable pool merge (all functions)
//   armorcomp-denc         : DataEncodingPass         — integer local var memory encoding (annotation mode)
//   armorcomp-denc-all     : DataEncodingPass         — integer local var memory encoding (all functions)
//   armorcomp-fsig         : FuncSigObfPass           — function signature obfuscation (annotation mode)
//   armorcomp-fsig-all     : FuncSigObfPass           — function signature obfuscation (all functions)
//   armorcomp-dpoison      : DwarfPoisonPass          — DWARF CFI table poisoning (annotation mode)
//   armorcomp-dpoison-all  : DwarfPoisonPass          — DWARF CFI table poisoning (all functions)
//   armorcomp-ntc          : NeonTypeConfusionPass    — AArch64 NEON/FP type confusion (annotation mode)
//   armorcomp-ntc-all      : NeonTypeConfusionPass    — AArch64 NEON/FP type confusion (all AArch64 fns)
//   armorcomp-sob          : SwitchObfPass             — switch statement obfuscation (annotation mode)
//   armorcomp-sob-all      : SwitchObfPass             — switch statement obfuscation (all functions)
//   armorcomp-rvo          : ReturnValueObfPass        — return value XOR obfuscation (annotation mode)
//   armorcomp-rvo-all      : ReturnValueObfPass        — return value XOR obfuscation (all fn types)
//   armorcomp-lro          : LRObfPass                 — link register XOR obfuscation (annotation mode, AArch64 only)
//   armorcomp-lro-all      : LRObfPass                 — link register XOR obfuscation (all AArch64 fns)
//   armorcomp-gepo         : GEPObfPass                — GEP index XOR obfuscation (annotation mode)
//   armorcomp-gepo-all     : GEPObfPass                — GEP index XOR obfuscation (all functions)
//   armorcomp-jci          : JunkCodePass              — junk code injection (annotation mode)
//   armorcomp-jci-all      : JunkCodePass              — junk code injection (all functions)
//   armorcomp-fapi         : FakeAPICallPass           — fake API call injection (annotation mode)
//   armorcomp-fapi-all     : FakeAPICallPass           — fake API call injection (all functions)
//   armorcomp-pxor         : PointerXorPass            — pointer local-var XOR encoding (annotation mode)
//   armorcomp-pxor-all     : PointerXorPass            — pointer local-var XOR encoding (all functions)
//   armorcomp-asp          : ArithmeticStatePass       — CFF state-var XOR encoding / anti-d810 (annotation mode)
//   armorcomp-asp-all      : ArithmeticStatePass       — CFF state-var XOR encoding (all functions)
//   armorcomp-gpo          : GlobalPointerObfuscationPass — fn-ptr global encryption (annotation mode)
//   armorcomp-gpo-all      : GlobalPointerObfuscationPass — fn-ptr global encryption (all eligible)
//   armorcomp-lob          : LoopObfuscationPass       — loop preheader/header junk (annotation mode)
//   armorcomp-lob-all      : LoopObfuscationPass       — loop obfuscation (all functions)
//
// Auto-run order at optimizer-last EP (annotation mode):
//   1. StrEncPass               (module) — encrypt string literals → .data ciphertext
//   2. GlobalEncPass            (module) — encrypt integer GV initializers → .data ciphertext
//   2.5 GlobalPointerObfuscationPass (module) — encrypt fn-ptr globals → null in binary, ctor decode
//   3. SwitchObfPass            (fn)    — replace SwitchInst with dense jump-table + indirectbr + XOR
//   4. SplitPass                (fn)    — split BBs to inflate CFG before BCF/CFF
//   5. SubPass                  (fn)    — substitute arithmetic/logic instructions
//   6. MBAPass                  (fn)    — MBA rewrite on top of substituted instructions
//   7. ConditionObfPass         (fn)    — add opaque noise to ICmpInst operands; IDA can't resolve conditions
//   8. DataEncodingPass         (fn)    — XOR encode/decode wrappers around every local var store/load
//   9. JunkCodePass             (fn)    — dead arithmetic chains per BB; asm sideeffect sink;
//                                         CO (step 10) further obfuscates JCI's own constants
//  10. ConstObfPass             (fn)    — hide integer constants (including DENC/JCI keys) behind XOR-key split
//  11. GEPObfPass               (fn)    — replace constant GEP indices with volatile-zero XOR;
//                                         defeats IDA struct/array/vtable field recognition
//  12. FlattenDataFlowPass      (fn)    — merge allocas into obfuscated byte pool
//  13. OutlinePass              (fn)    — extract each non-entry BB into __armorcomp_outline_N
//  14. BCFPass                  (fn)    — add bogus branches on substituted + split CFG
//  15. OpaquePredicatePass      (fn)    — add dead-end branches with varied predicate formulas
//  16. CFFPass                  (fn)    — flatten everything into dispatch switch
//  17. RetAddrObfPass           (fn)    — sub/add SP around every call (IDA sp_delta UNKNOWN)
//  18. IndirectCallPass         (fn)    — replace direct calls with opaque-ptr indirect calls
//  19. IndirectBranchPass       (fn)    — replace direct branches with indirectbr
//  20. IndirectGlobalVariablePass(fn)   — replace GV operands with proxy-ptr loads
//  21. FuncWrapPass             (fn)    — call-graph indirection wrappers
//  22. FuncSigObfPass           (fn)    — fake arg reads + fake ret-val writes → IDA wrong prototype
//  23. SPOPass                  (fn)    — volatile SP sub/add defeats IDA runtime SP tracking
//  24. NeonTypeConfusionPass    (fn)    — fmov GPR↔SIMD roundtrips at entry/exit confuse IDA
//                                         type inference; integer params annotated as float/double
//  25. ReturnValueObfPass       (fn)    — XOR return value with volatile zero before ret;
//                                         IDA cannot determine return type or value statically;
//                                         target-independent pure IR (no inline asm)
//  26. LRObfPass                (fn)    — eor x30, x30, volatile_zero before ret;
//                                         IDA cannot resolve return address → caller xrefs become
//                                         JUMPOUT(); AArch64-only (Triple guard)
//  27. DwarfPoisonPass          (fn)    — .cfi_remember_state/fake CFA/.cfi_restore_state →
//                                         .eh_frame rows with sp+524288/x15/x16/undef LR+FP;
//                                         defeats IDA DWARF-table-based sp_delta analysis
//
// HelloPass auto-inserts at pipeline-start for diagnostic coverage.
//===----------------------------------------------------------------------===//

#include "ArmorComp/BCFPass.h"
#include "ArmorComp/CFFPass.h"
#include "ArmorComp/DataEncodingPass.h"
#include "ArmorComp/FlattenDataFlowPass.h"
#include "ArmorComp/DwarfPoisonPass.h"
#include "ArmorComp/FuncSigObfPass.h"
#include "ArmorComp/NeonTypeConfusionPass.h"
#include "ArmorComp/ReturnValueObfPass.h"
#include "ArmorComp/GEPObfPass.h"
#include "ArmorComp/JunkCodePass.h"
#include "ArmorComp/FakeAPICallPass.h"
#include "ArmorComp/PointerXorPass.h"
#include "ArmorComp/ArithmeticStatePass.h"
#include "ArmorComp/GlobalPointerObfuscationPass.h"
#include "ArmorComp/LoopObfuscationPass.h"
#include "ArmorComp/VMPPass.h"
#include "ArmorComp/LRObfPass.h"
#include "ArmorComp/SwitchObfPass.h"
#include "ArmorComp/GlobalEncPass.h"
#include "ArmorComp/OpaquePredicatePass.h"
#include "ArmorComp/OutlinePass.h"
#include "ArmorComp/ConstObfPass.h"
#include "ArmorComp/FuncWrapPass.h"
#include "ArmorComp/IndirectBranchPass.h"
#include "ArmorComp/RetAddrObfPass.h"
#include "ArmorComp/IndirectCallPass.h"
#include "ArmorComp/IndirectGlobalVariablePass.h"
#include "ArmorComp/ConditionObfPass.h"
#include "ArmorComp/MBAPass.h"
#include "ArmorComp/SPOPass.h"
#include "ArmorComp/SplitPass.h"
#include "ArmorComp/StrEncPass.h"
#include "ArmorComp/SubPass.h"

// P0/P1/P2 新增 Pass (反调试 / 防篡改 / 控制流随机化)
#include "ArmorComp/AntiDebugPass.h"
#include "ArmorComp/AntiTamperPass.h"
#include "ArmorComp/ControlFlowRandomizationPass.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

//===----------------------------------------------------------------------===//
// HelloPass — FunctionPass，打印每个函数名
//===----------------------------------------------------------------------===//
struct HelloPass : PassInfoMixin<HelloPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager & /*AM*/) {
    errs() << "[ArmorComp] function: " << F.getName()
           << " (" << F.size() << " basic blocks)\n";
    return PreservedAnalyses::all();  // 不修改任何内容
  }

  // 即使函数标了 optnone 也要运行（便于调试）
  static bool isRequired() { return true; }
};

} // anonymous namespace

//===----------------------------------------------------------------------===//
// Plugin registration
// NDK clang 调用 llvmGetPassPluginInfo() 来发现和注册 passes
//===----------------------------------------------------------------------===//
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "ArmorComp",
    "0.25.0",
    [](PassBuilder &PB) {

      // ── HelloPass: pipeline-start auto-insert ──────────────────────────
      // Runs on every compilation unit — useful for verifying the plugin
      // loaded correctly and seeing which functions are being compiled.
      PB.registerPipelineStartEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel /*Level*/) {
          MPM.addPass(createModuleToFunctionPassAdaptor(HelloPass()));
        }
      );

      // ── All passes: optimizer-last auto-insert (annotation mode) ──────────
      // Execution order is intentional:
      //   STRENC → GENC → GPO → VMP → SOB → SPLIT → SUB → MBA → LOB → COB → DENC → PXOR → JCI → FAPI → CO → GEPO → DF → OUTLINE → BCF → OP → CFF → ASP → RAO → ICALL → IBR → IGV → FW → FSIG → SPO → NTC → RVO → LRO → DPOISON
      //
      //   STRENC  (module) : encrypt strings before any function transform.
      //   GENC    (module) : encrypt integer GV initializers — both data-section
      //                       passes run together before function-level transforms.
      //   SPLIT   (fn)     : inflate BB count so BCF+CFF produce more cases.
      //   SUB     (fn)     : complicate instruction patterns before MBA/BCF.
      //   MBA     (fn)     : mixed boolean-arithmetic rewrite on substituted ops.
      //   CO      (fn)     : hide integer constants after SUB/MBA rewrites.
      //   DF      (fn)     : merge all allocas into a single obfuscated byte pool;
      //                       runs after CO so the pool GEP indices blend with the
      //                       existing XOR-key obfuscation patterns; before OUTLINE
      //                       so the outlined BBs operate on pool pointers.
      //   OUTLINE (fn)     : extract each non-entry BB into __armorcomp_outline_N;
      //                       runs after DF so outlined helpers carry pool-access
      //                       code; before BCF so the outlined helpers receive
      //                       bogus-branch inflation.
      //   BCF     (fn)     : add bogus branches on split+substituted+MBA CFG.
      //   OP      (fn)     : add dead-end branches using 6 varied opaque predicates;
      //                       runs after BCF so BCF's bogus BBs also receive OPP
      //                       branches; before CFF so dead BBs appear as switch cases.
      //   CFF     (fn)     : flatten everything into a switch dispatch loop.
      //   RAO     (fn)     : insert sub/add SP around every call — runs before
      //                       ICALL so direct calls are still visible; combined
      //                       with SPO completely defeats IDA sp_delta analysis.
      //   ICALL   (fn)     : replace direct calls with opaque-pointer indirect calls.
      //   IBR     (fn)     : replace direct branches with indirectbr.
      //   IGV     (fn)     : replace GV operands with proxy-ptr loads.
      //   FW      (fn)     : add call-graph indirection wrappers for remaining
      //                       direct calls — runs after ICALL/IBR/IGV so all
      //                       CFG/GV transforms are stable; before SPO so the
      //                       wrapper bodies also get SP obfuscation.
      //   FSIG    (fn)     : fake arg reads + fake ret-val writes → IDA wrong prototype.
      //   SPO     (fn)     : volatile SP sub/add at entry/exit defeats IDA runtime SP tracking.
      //   NTC     (fn)     : fmov GPR↔SIMD roundtrips confuse IDA type inference;
      //                       integer parameters annotated as float/double in Hex-Rays F5.
      //                       AArch64-only; no-op on other targets.
      //   DPOISON (fn)     : .cfi_remember_state/fake CFA/.cfi_restore_state injections →
      //                       .eh_frame rows with enormous offsets / scratch-reg bases /
      //                       undef LR+FP; defeats IDA DWARF-table sp_delta analysis.
      //                       Runs last — DWARF rows reflect the fully-transformed IR.
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel /*Level*/) {
          // STRENC: annotate("strenc")  [module pass]
          MPM.addPass(StrEncPass(/*annotateOnly=*/true));
          // GENC: annotate("genc")  [module pass] — encrypt integer GV initializers
          //    after STRENC so both data-section passes share the same ctor
          //    injection slot; before SOB/SPLIT/SUB/MBA so function-level passes
          //    operate on already-encrypted global references.
          MPM.addPass(GlobalEncPass(/*annotateOnly=*/true));
          // GPO: annotate("gpo")  [module pass] — encrypt function-pointer globals;
          //    null-out initializer in binary, decode via ctor before main().
          //    Runs after GENC (both are data-section module passes that share
          //    ctor infrastructure); before VMP/SOB/SPLIT so the null-pointer
          //    state is what all function-level passes see.
          MPM.addPass(GlobalPointerObfuscationPass(/*annotateOnly=*/true));
          // VMP: annotate("vmp")  — virtualize function into custom bytecode VM;
          //    runs after STRENC/GENC so string/global encryption is already
          //    in place; runs before SOB/SPLIT/SUB so all downstream passes
          //    operate on the generated dispatcher stub (multi-layer obfuscation).
          //    Functions with unsupported IR (calls, FP, SIMD) are silently skipped.
          MPM.addPass(createModuleToFunctionPassAdaptor(VMPPass(/*annotateOnly=*/true)));
          // SOB: annotate("sob")  — replace SwitchInst with dense jump-table
          //    + volatile load + ptrtoint/XOR/inttoptr + indirectbr.
          //    Runs after the two module passes (STRENC, GENC) and before SPLIT
          //    so SPLIT inflates the BB count of SOB-transformed code.
          //    The indirectbr SOB creates is later flattened by CFF;
          //    the bounds-check ICmpInst is later noised by COB.
          //    Orthogonal to IndirectBranchPass (IBR only handles BranchInst).
          MPM.addPass(createModuleToFunctionPassAdaptor(SwitchObfPass(/*annotateOnly=*/true)));
          // SPLIT: annotate("split")
          MPM.addPass(createModuleToFunctionPassAdaptor(SplitPass(/*annotateOnly=*/true)));
          // SUB: annotate("sub")
          MPM.addPass(createModuleToFunctionPassAdaptor(SubPass(/*annotateOnly=*/true)));
          // MBA: annotate("mba")
          MPM.addPass(createModuleToFunctionPassAdaptor(MBAPass(/*annotateOnly=*/true)));
          // LOB: annotate("lob")  — loop obfuscation via LoopAnalysis;
          //    inject preheader junk + header noise + fake invariant alloca.
          //    Runs after MBA so junk wraps already-MBA-obfuscated loop code;
          //    MUST run before BCF/CFF because those transforms destroy loop
          //    structure (CFF turns loops into switch-dispatcher).
          MPM.addPass(createModuleToFunctionPassAdaptor(LoopObfuscationPass(/*annotateOnly=*/true)));
          // COB: annotate("cob")  — add opaque noise to both operands of every
          //    ICmpInst so IDA Hex-Rays cannot statically resolve comparison
          //    conditions; runs after MBA so condition noise wraps already
          //    MBA-obfuscated operands; before DENC/CO so their keys also
          //    cover the noise constants introduced by COB.
          MPM.addPass(createModuleToFunctionPassAdaptor(ConditionObfPass(/*annotateOnly=*/true)));
          // DENC: annotate("denc")  — XOR encode/decode wrappers around every
          //    integer alloca store/load; runs after SUB/MBA so encoding wraps
          //    already-substituted ops; before CO so CO obfuscates DENC's keys;
          //    before DF so DF can still see and merge the original allocas.
          MPM.addPass(createModuleToFunctionPassAdaptor(DataEncodingPass(/*annotateOnly=*/true)));
          // PXOR: annotate("pxor")  — XOR encode/decode wrappers around pointer
          //    alloca store/load (complements DENC which covers integer allocas).
          //    Runs right after DENC so both integer and pointer locals are
          //    encoded before JCI/CO obfuscate their patterns further.
          MPM.addPass(createModuleToFunctionPassAdaptor(PointerXorPass(/*annotateOnly=*/true)));
          // JCI: annotate("jci")  — inject dead arithmetic chains (4–7 ops,
          //    xorshift64-PRNG constants) into every BB before the terminator.
          //    Each chain loads @__armorcomp_jci_zero (= 0), runs arithmetic,
          //    then feeds the result into an empty asm sideeffect sink.
          //    Runs after DENC/PXOR so chains are inserted after encoding wrappers;
          //    before CO so CO additionally obfuscates JCI's own constants —
          //    two-layer obfuscation: chain ops are XOR-split by CO on top.
          //    IDA Hex-Rays F5 effect: extra dead local variables in each BB,
          //    all tracing back to the volatile zero load.
          MPM.addPass(createModuleToFunctionPassAdaptor(JunkCodePass(/*annotateOnly=*/true)));
          // FAPI: annotate("fapi")  — inject real libc calls (getpid/getpagesize)
          //    before each BB's terminator; results consumed by asm sideeffect sinks.
          //    Unlike JCI (dead arithmetic), FAPI uses genuine side-effect calls
          //    that no analysis tool can prove are no-ops.
          //    Runs after JCI so the real calls appear after JCI's arithmetic;
          //    before CO so CO doesn't try to obfuscate FAPI's (integer) constants.
          MPM.addPass(createModuleToFunctionPassAdaptor(FakeAPICallPass(/*annotateOnly=*/true)));
          // CO: annotate("co")  — hide integer constants after SUB/MBA have
          //    rewritten the operators; any new constants MBA introduced are
          //    also obfuscated before GEPO and DF.
          MPM.addPass(createModuleToFunctionPassAdaptor(ConstObfPass(/*annotateOnly=*/true)));
          // GEPO: annotate("gepo")  — replace non-zero ConstantInt GEP index
          //    operands with volatile-zero XOR expressions.  Complements CO
          //    (CO: BinaryOperator/ICmpInst constants; GEPO: GEP index constants).
          //    Runs after CO so CO does not further obfuscate GEPO's own XOR-key
          //    constants; before DF so DF's pool-access GEPs (already using their
          //    own obfuscated non-constant indices) are not touched.
          //    IDA effect: struct field offsets, array strides, vtable slot indices
          //    become volatile-loaded XOR expressions → struct/class layout
          //    unrecoverable from static analysis.
          MPM.addPass(createModuleToFunctionPassAdaptor(GEPObfPass(/*annotateOnly=*/true)));
          // DF: annotate("df")  — merge all allocas into a single obfuscated
          //    byte pool; runs after CO so the XOR-key GEP indices blend with
          //    the existing constant obfuscation, before OUTLINE so outlined
          //    BBs operate on pool pointers rather than named stack slots.
          MPM.addPass(createModuleToFunctionPassAdaptor(FlattenDataFlowPass(/*annotateOnly=*/true)));
          // OUTLINE: annotate("outline")  — extract each non-entry BB into an
          //    independent internal function (__armorcomp_outline_N); runs after
          //    CO so the outlined helpers carry constant-obfuscated code, and
          //    before BCF so the helpers receive bogus-branch inflation.
          MPM.addPass(createModuleToFunctionPassAdaptor(OutlinePass(/*annotateOnly=*/true)));
          // BCF: annotate("bcf")
          MPM.addPass(createModuleToFunctionPassAdaptor(BCFPass(/*annotateOnly=*/true)));
          // OP: annotate("op")  — add dead-end branches with varied predicate
          //    formulas; runs after BCF so BCF's bogus BBs also get OPP branches,
          //    and before CFF so OPP dead BBs appear as switch cases.
          MPM.addPass(createModuleToFunctionPassAdaptor(OpaquePredicatePass(/*annotateOnly=*/true)));
          // CFF: annotate("cff")
          MPM.addPass(createModuleToFunctionPassAdaptor(CFFPass(/*annotateOnly=*/true)));
          // ASP: annotate("asp")  — XOR-encode CFF state variable constants;
          //    all "store i32 STATE_N, %sw_var" → "store i32 (STATE_N XOR K)"
          //    and all SwitchInst case constants → (case_val XOR K).
          //    Runs IMMEDIATELY after CFF so the state variable pattern is
          //    cleanly detectable; before RAO/ICALL/IBR which further mutate
          //    the IR and might break the alloca-only-used-by-switch invariant.
          //    Defeats d810/msynack automated CFF deobfuscation tools.
          MPM.addPass(createModuleToFunctionPassAdaptor(ArithmeticStatePass(/*annotateOnly=*/true)));
          // RAO: annotate("rao")  — insert sub/add SP noise around every call;
          //    must run before ICALL (ICALL converts direct calls to indirect,
          //    making CI->getCalledFunction() null and skipping them in RAO).
          MPM.addPass(createModuleToFunctionPassAdaptor(RetAddrObfPass(/*annotateOnly=*/true)));
          // ICALL: annotate("icall")
          MPM.addPass(createModuleToFunctionPassAdaptor(IndirectCallPass(/*annotateOnly=*/true)));
          // IBR: annotate("ibr")
          MPM.addPass(createModuleToFunctionPassAdaptor(IndirectBranchPass(/*annotateOnly=*/true)));
          // IGV: annotate("igv")
          MPM.addPass(createModuleToFunctionPassAdaptor(IndirectGlobalVariablePass(/*annotateOnly=*/true)));
          // FW: annotate("fw")  — wrap remaining direct calls with internal
          //    forwarder functions; runs after ICALL/IBR/IGV for a stable IR.
          MPM.addPass(createModuleToFunctionPassAdaptor(FuncWrapPass(/*annotateOnly=*/true)));
          // FSIG: annotate("fsig")  — fake argument reads at entry (x1/x2/x3)
          //    and fake return-value writes at exit (x1/x2); poisons IDA's
          //    register-liveness analysis so Hex-Rays infers wrong prototype.
          //    Runs after FW so wrapper bodies also receive boundary obfuscation;
          //    before SPO so FSIG's entry/exit asm is still visible to IDA's
          //    function prototype analysis before SP noise is layered on top.
          MPM.addPass(createModuleToFunctionPassAdaptor(FuncSigObfPass(/*annotateOnly=*/true)));
          // SPO: annotate("spo")  — volatile SP sub/add at function entry/exit;
          //    combined with RAO (per-call sub/add) for complete sp_delta
          //    destruction via IDA's runtime-trace-based SP analysis.
          MPM.addPass(createModuleToFunctionPassAdaptor(SPOPass(/*annotateOnly=*/true)));
          // NTC: annotate("ntc")  — inject fmov GPR↔SIMD roundtrips at function
          //    entry and before each ret.  Source operand is a volatile i32 load
          //    of @__armorcomp_ntc_zero (= 0 at runtime).  IDA type inference sees
          //    integer values flowing through s16-s19 and annotates them as float.
          //    AArch64-only (no-op on other targets via Triple guard).
          //    Runs after SPO so the SP obfuscation is already applied; before
          //    DPOISON so the DWARF rows reflect the final fmov-augmented IR.
          MPM.addPass(createModuleToFunctionPassAdaptor(NeonTypeConfusionPass(/*annotateOnly=*/true)));
          // RVO: annotate("rvo")  — XOR return value with volatile i64 load of
          //    @__armorcomp_rvo_zero (= 0) before each ret.  Runtime no-op but IDA
          //    cannot prove the XOR operand is zero, so return-type inference fails.
          //    Complements NTC (type confusion via SIMD registers) and FSIG (fake
          //    arg reads + x1/x2 writes): together all three make the complete
          //    function prototype — parameter types, count, AND return type —
          //    unrecoverable from static analysis.  Pure IR; target-independent.
          //    Runs after NTC so fmov roundtrips are already emitted at exit;
          //    before LRO so LRO's eor x30 is the outermost ret-side operation.
          MPM.addPass(createModuleToFunctionPassAdaptor(ReturnValueObfPass(/*annotateOnly=*/true)));
          // LRO: annotate("lro")  — inject inline asm "eor x30, x30, volatile_zero"
          //    before each ReturnInst.  AArch64-only (Triple guard inside pass).
          //    x30 is the link register; XOR with volatile zero is a runtime no-op
          //    but IDA cannot resolve the return address → caller xrefs become
          //    JUMPOUT().  Orthogonal to RVO (xors return VALUE in x0) and SPO/RAO
          //    (corrupt SP) and DPOISON (corrupts .eh_frame CFA rows).
          //    Runs after RVO so the return value obfuscation is already in place;
          //    before DPOISON so DWARF rows reflect the final eor-augmented IR.
          MPM.addPass(createModuleToFunctionPassAdaptor(LRObfPass(/*annotateOnly=*/true)));
          // DPOISON: annotate("dpoison")  — inject .cfi_remember_state / fake
          //    .cfi_def_cfa rows / .cfi_restore_state at function entry, each BB,
          //    and before each ret.  Runs last (after LRO) so injected DWARF rows
          //    reflect the fully-transformed IR including eor x30 instructions.
          //    Attacks a different IDA analysis path from SPO: instead of the
          //    runtime SP tracker, this defeats IDA's DWARF table reader that
          //    checks the .eh_frame CFA records.
          MPM.addPass(createModuleToFunctionPassAdaptor(DwarfPoisonPass(/*annotateOnly=*/true)));

          // ── P1/P2 新增 Pass (运行时保护 + 布局混淆) ──────────────────────
          // ADB: annotate("adb") — 反调试检测 (ptrace/clock/env)
          MPM.addPass(createModuleToFunctionPassAdaptor(AntiDebugPass(/*annotateOnly=*/true)));
          // AT: annotate("at") — 防篡改完整性校验 (canary guard)
          MPM.addPass(createModuleToFunctionPassAdaptor(AntiTamperPass(/*annotateOnly=*/true)));
          // CFR: annotate("cfr") — 控制流随机布局
          MPM.addPass(createModuleToFunctionPassAdaptor(
              ControlFlowRandomizationPass(/*annotateOnly=*/true,
                                           /*splitBlocks=*/false,
                                           /*fakeEntries=*/false)));
        }
      );

      // ── All passes: explicit -passes= registration ─────────────────────
      PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM,
           ArrayRef<PassBuilder::PipelineElement> /*InnerPipeline*/) -> bool {

          // armorcomp-hello — diagnostic: print function names
          if (Name == "armorcomp-hello") {
            FPM.addPass(HelloPass());
            return true;
          }

          // armorcomp-sob — switch statement obfuscation (annotation mode)
          // Replaces SwitchInst with dense jump-table + volatile table load +
          // ptrtoint/XOR/inttoptr + indirectbr.  Orthogonal to IBR (which only
          // handles BranchInst).  Annotation: __attribute__((annotate("sob"))).
          if (Name == "armorcomp-sob") {
            FPM.addPass(SwitchObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-sob-all — switch statement obfuscation (all functions)
          if (Name == "armorcomp-sob-all") {
            FPM.addPass(SwitchObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-cff — CFG flattening (annotation mode)
          // Only functions annotated with __attribute__((annotate("cff")))
          // are flattened.  Safe default: non-annotated code is untouched.
          if (Name == "armorcomp-cff") {
            FPM.addPass(CFFPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-cff-all — CFG flattening (aggressive mode)
          // Every function with more than one basic block is flattened.
          // Use with caution: significantly increases binary size.
          if (Name == "armorcomp-cff-all") {
            FPM.addPass(CFFPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-bcf — bogus control flow (annotation mode)
          if (Name == "armorcomp-bcf") {
            FPM.addPass(BCFPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-bcf-all — bogus control flow (aggressive mode)
          if (Name == "armorcomp-bcf-all") {
            FPM.addPass(BCFPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-op — opaque predicate insertion (annotation mode)
          // Splits each non-entry BB and adds a dead-end branch using one of
          // 6 opaque predicate formulas.  Recommended: run after BCF, before CFF.
          if (Name == "armorcomp-op") {
            FPM.addPass(OpaquePredicatePass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-op-all — opaque predicate insertion (all functions)
          if (Name == "armorcomp-op-all") {
            FPM.addPass(OpaquePredicatePass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-sub — instruction substitution (annotation mode)
          if (Name == "armorcomp-sub") {
            FPM.addPass(SubPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-sub-all — instruction substitution (all functions)
          if (Name == "armorcomp-sub-all") {
            FPM.addPass(SubPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-split — basic block splitting (annotation mode)
          if (Name == "armorcomp-split") {
            FPM.addPass(SplitPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-split-all — basic block splitting (all functions)
          if (Name == "armorcomp-split-all") {
            FPM.addPass(SplitPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-mba — mixed boolean-arithmetic obfuscation (annotation mode)
          if (Name == "armorcomp-mba") {
            FPM.addPass(MBAPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-mba-all — mixed boolean-arithmetic (all functions)
          if (Name == "armorcomp-mba-all") {
            FPM.addPass(MBAPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-cob — comparison obfuscation (annotation mode)
          // Adds opaque noise to both operands of every ICmpInst in annotate("cob")
          // functions so IDA Hex-Rays cannot statically resolve condition expressions.
          // Orthogonal to MBA/SUB which only transform BinaryOperator instructions.
          if (Name == "armorcomp-cob") {
            FPM.addPass(ConditionObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-cob-all — comparison obfuscation (all functions)
          if (Name == "armorcomp-cob-all") {
            FPM.addPass(ConditionObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-icall — indirect call obfuscation (annotation mode)
          if (Name == "armorcomp-icall") {
            FPM.addPass(IndirectCallPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-icall-all — indirect call obfuscation (all functions)
          if (Name == "armorcomp-icall-all") {
            FPM.addPass(IndirectCallPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-ibr — indirect branch obfuscation (annotation mode)
          if (Name == "armorcomp-ibr") {
            FPM.addPass(IndirectBranchPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-ibr-all — indirect branch obfuscation (all functions)
          if (Name == "armorcomp-ibr-all") {
            FPM.addPass(IndirectBranchPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-igv — indirect global variable (annotation mode)
          if (Name == "armorcomp-igv") {
            FPM.addPass(IndirectGlobalVariablePass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-igv-all — indirect global variable (all functions)
          if (Name == "armorcomp-igv-all") {
            FPM.addPass(IndirectGlobalVariablePass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-co — integer constant obfuscation (annotation mode)
          if (Name == "armorcomp-co") {
            FPM.addPass(ConstObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-co-all — integer constant obfuscation (all functions)
          if (Name == "armorcomp-co-all") {
            FPM.addPass(ConstObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-outline — basic block outlining (annotation mode)
          // Each non-entry BB in annotate("outline") functions is extracted into
          // an independent internal function __armorcomp_outline_N.
          if (Name == "armorcomp-outline") {
            FPM.addPass(OutlinePass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-outline-all — basic block outlining (all functions)
          if (Name == "armorcomp-outline-all") {
            FPM.addPass(OutlinePass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-df — data flow flattening / stack pool merge (annotation mode)
          // Merges all statically-sized allocas in annotate("df") functions into
          // a single byte pool with obfuscated GEP indices.
          if (Name == "armorcomp-df") {
            FPM.addPass(FlattenDataFlowPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-df-all — data flow flattening (all functions)
          if (Name == "armorcomp-df-all") {
            FPM.addPass(FlattenDataFlowPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-denc — integer local variable memory encoding (annotation mode)
          // XOR encode/decode wrappers around every integer alloca store/load in
          // annotate("denc") functions.  Stack memory contains only encoded values.
          if (Name == "armorcomp-denc") {
            FPM.addPass(DataEncodingPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-denc-all — integer local variable memory encoding (all functions)
          if (Name == "armorcomp-denc-all") {
            FPM.addPass(DataEncodingPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-spo — stack pointer obfuscation (annotation mode)
          if (Name == "armorcomp-spo") {
            FPM.addPass(SPOPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-spo-all — stack pointer obfuscation (all functions)
          if (Name == "armorcomp-spo-all") {
            FPM.addPass(SPOPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-rao — return addr / call-frame obfuscation (annotation mode)
          if (Name == "armorcomp-rao") {
            FPM.addPass(RetAddrObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-rao-all — call-frame obfuscation (all functions)
          if (Name == "armorcomp-rao-all") {
            FPM.addPass(RetAddrObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-fw — function wrapper indirection (annotation mode)
          if (Name == "armorcomp-fw") {
            FPM.addPass(FuncWrapPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-fw-all — function wrapper indirection (all functions)
          if (Name == "armorcomp-fw-all") {
            FPM.addPass(FuncWrapPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-fsig — function signature obfuscation (annotation mode)
          // Injects fake arg reads (x1/x2/x3) at entry and fake ret-val writes
          // (x1/x2) at exit to confuse IDA Hex-Rays prototype analysis.
          if (Name == "armorcomp-fsig") {
            FPM.addPass(FuncSigObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-fsig-all — function signature obfuscation (all functions)
          if (Name == "armorcomp-fsig-all") {
            FPM.addPass(FuncSigObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-dpoison — DWARF CFI table poisoning (annotation mode)
          // Injects .cfi_remember_state / fake .cfi_def_cfa / .cfi_restore_state
          // at function entry, each BB, and before each ret.  Poisons .eh_frame
          // with impossible CFA values (sp+524288, x15+16, etc.) and undef LR/FP
          // rows, defeating IDA's DWARF-table-based sp_delta / frame analysis.
          if (Name == "armorcomp-dpoison") {
            FPM.addPass(DwarfPoisonPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-dpoison-all — DWARF CFI table poisoning (all AArch64 functions)
          if (Name == "armorcomp-dpoison-all") {
            FPM.addPass(DwarfPoisonPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-rvo — return value XOR obfuscation (annotation mode)
          // XOR-encodes the return value of i8/i16/i32/i64/ptr-returning functions
          // annotated with annotate("rvo") using a volatile-zero load.  IDA cannot
          // determine the return type or value.  Pure IR; no inline asm.
          if (Name == "armorcomp-rvo") {
            FPM.addPass(ReturnValueObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-rvo-all — return value XOR obfuscation (all eligible functions)
          if (Name == "armorcomp-rvo-all") {
            FPM.addPass(ReturnValueObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-ntc — AArch64 NEON/FP type confusion (annotation mode)
          // Injects fmov GPR↔SIMD roundtrips at function entry and before each ret.
          // Volatile i32 load of @__armorcomp_ntc_zero (= 0) is moved through
          // s16-s17 (entry) and s18-s19 (ret).  IDA type inference annotates integer
          // parameters as float/double.  AArch64-only; no-op on other targets.
          if (Name == "armorcomp-ntc") {
            FPM.addPass(NeonTypeConfusionPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-ntc-all — NEON/FP type confusion (all AArch64 functions)
          if (Name == "armorcomp-ntc-all") {
            FPM.addPass(NeonTypeConfusionPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-lro — link register XOR obfuscation (annotation mode)
          // Injects inline asm "eor x30, x30, <volatile_zero>" before each ret
          // in annotate("lro") functions.  AArch64-only; no-op on other targets.
          // Breaks caller xref analysis in IDA: return address becomes unresolvable.
          if (Name == "armorcomp-lro") {
            FPM.addPass(LRObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-lro-all — link register XOR obfuscation (all AArch64 functions)
          if (Name == "armorcomp-lro-all") {
            FPM.addPass(LRObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-gepo — GEP index XOR obfuscation (annotation mode)
          // Replaces non-zero ConstantInt GEP index operands with volatile-zero
          // XOR expressions in annotate("gepo") functions.  Defeats IDA Pro's
          // struct field recognition, array subscript analysis, and vtable
          // dispatch identification.  Orthogonal to CO (which targets
          // BinaryOperator/ICmpInst constants, explicitly skipping GEPs).
          if (Name == "armorcomp-gepo") {
            FPM.addPass(GEPObfPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-gepo-all — GEP index XOR obfuscation (all functions)
          if (Name == "armorcomp-gepo-all") {
            FPM.addPass(GEPObfPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-jci — junk code injection (annotation mode)
          // Inserts dead arithmetic chains into each BB of annotate("jci") functions.
          // Volatile-zero base + 4–7 ops + asm sideeffect sink.  CO (if applied later)
          // additionally obfuscates JCI's own arithmetic constants.
          if (Name == "armorcomp-jci") {
            FPM.addPass(JunkCodePass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-jci-all — junk code injection (all functions)
          if (Name == "armorcomp-jci-all") {
            FPM.addPass(JunkCodePass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-fapi — fake API call injection (annotation mode)
          // Injects real libc calls (getpid/getpagesize) with asm sideeffect sinks.
          if (Name == "armorcomp-fapi") {
            FPM.addPass(FakeAPICallPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-fapi-all — fake API call injection (all functions)
          if (Name == "armorcomp-fapi-all") {
            FPM.addPass(FakeAPICallPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-pxor — pointer local variable XOR encoding (annotation mode)
          // XOR-encodes pointer-typed alloca slots; complements DENC for integers.
          if (Name == "armorcomp-pxor") {
            FPM.addPass(PointerXorPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-pxor-all — pointer XOR encoding (all functions)
          if (Name == "armorcomp-pxor-all") {
            FPM.addPass(PointerXorPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-asp — arithmetic state pass / CFF state var XOR encoding (annotation mode)
          // XOR-encodes CFF state variable constants to defeat d810/msynack.
          // Run AFTER CFF so the state variable pattern is cleanly detectable.
          if (Name == "armorcomp-asp") {
            FPM.addPass(ArithmeticStatePass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-asp-all — arithmetic state encoding (all functions)
          if (Name == "armorcomp-asp-all") {
            FPM.addPass(ArithmeticStatePass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-lob — loop obfuscation (annotation mode)
          // Injects preheader/header junk and fake invariant into natural loops.
          // Run BEFORE BCF/CFF.
          if (Name == "armorcomp-lob") {
            FPM.addPass(LoopObfuscationPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-lob-all — loop obfuscation (all functions)
          if (Name == "armorcomp-lob-all") {
            FPM.addPass(LoopObfuscationPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-vmp — Virtual Machine Protection (annotation mode)
          // Lifts annotate("vmp") functions to VMP bytecode + dispatcher.
          // Functions with unsupported IR are silently skipped with a warning.
          if (Name == "armorcomp-vmp") {
            FPM.addPass(VMPPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-vmp-all — VMP (all functions)
          if (Name == "armorcomp-vmp-all") {
            FPM.addPass(VMPPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-adb — anti-debug detection (annotation mode)
          if (Name == "armorcomp-adb") {
            FPM.addPass(AntiDebugPass(/*annotateOnly=*/true));
            return true;
          }
          if (Name == "armorcomp-adb-all") {
            FPM.addPass(AntiDebugPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-at — anti-tamper integrity check (annotation mode)
          if (Name == "armorcomp-at") {
            FPM.addPass(AntiTamperPass(/*annotateOnly=*/true));
            return true;
          }
          if (Name == "armorcomp-at-all") {
            FPM.addPass(AntiTamperPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-cfr — control flow randomization (annotation mode)
          if (Name == "armorcomp-cfr") {
            FPM.addPass(ControlFlowRandomizationPass(/*annotateOnly=*/true,
                                                     /*splitBlocks=*/false,
                                                     /*fakeEntries=*/false));
            return true;
          }
          if (Name == "armorcomp-cfr-all") {
            FPM.addPass(ControlFlowRandomizationPass(/*annotateOnly=*/false,
                                                     /*splitBlocks=*/false,
                                                     /*fakeEntries=*/false));
            return true;
          }
          if (Name == "armorcomp-cfr-aggressive") {
            FPM.addPass(ControlFlowRandomizationPass(/*annotateOnly=*/false,
                                                     /*splitBlocks=*/true,
                                                     /*fakeEntries=*/true));
            return true;
          }

          return false;
        }
      );

      // ── StrEncPass: explicit -passes= registration (module pass) ─────────
      // Module passes need a separate registerPipelineParsingCallback that
      // accepts a ModulePassManager instead of a FunctionPassManager.
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM,
           ArrayRef<PassBuilder::PipelineElement> /*InnerPipeline*/) -> bool {

          // armorcomp-strenc — string encryption (annotation mode)
          if (Name == "armorcomp-strenc") {
            MPM.addPass(StrEncPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-strenc-all — string encryption (all strings)
          if (Name == "armorcomp-strenc-all") {
            MPM.addPass(StrEncPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-genc — integer global variable encryption (annotation mode)
          // Encrypts ConstantInt initializers of globals used by annotate("genc")
          // functions; injects __armorcomp_genc_init ctor for runtime decryption.
          if (Name == "armorcomp-genc") {
            MPM.addPass(GlobalEncPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-genc-all — integer global variable encryption (all eligible)
          if (Name == "armorcomp-genc-all") {
            MPM.addPass(GlobalEncPass(/*annotateOnly=*/false));
            return true;
          }

          // armorcomp-gpo — function-pointer global encryption (annotation mode)
          // Null-outs fn-ptr global initializers; ctor decodes XOR-encrypted
          // companion globals at startup.  Defeats IDA static xref analysis.
          if (Name == "armorcomp-gpo") {
            MPM.addPass(GlobalPointerObfuscationPass(/*annotateOnly=*/true));
            return true;
          }

          // armorcomp-gpo-all — function-pointer global encryption (all eligible)
          if (Name == "armorcomp-gpo-all") {
            MPM.addPass(GlobalPointerObfuscationPass(/*annotateOnly=*/false));
            return true;
          }

          return false;
        }
      );
    }
  };
}
