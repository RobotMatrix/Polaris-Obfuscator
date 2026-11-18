#include "AArch64.h"
#include "AArch64InstrInfo.h"
#include "AArch64Subtarget.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ObfuscationSeed.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <vector>
using namespace llvm;

static uint32_t obfRand() { return (uint32_t)llvm::nextObfRandom(); }

// Defined with the S1 name generator further down; the S2 key/label need the
// same per-build seed and must not consume the junk-code RNG stream.
static uint64_t mixNameHash(uint64_t H, uint64_t V);
static uint64_t splitNameSeed();

// ---- S1 split-chunk symbols ----------------------------------------------
// The MIR split scatters basic blocks inside the enclosing symbol's interval,
// so Mach-O still reports one function per real function (exported-binaries/
// README.md, "Function Splitting").  With this flag every split chunk gets a
// non-temporary local label at its first instruction: ld64 turns those into
// nlist entries and LC_FUNCTION_STARTS entries, so the region reads as many
// small functions.  Off by default -- artifacts without the flag are byte
// identical to the previous behaviour.
static cl::opt<bool> SplitSymbols(
    "split-symbols", cl::Hidden, cl::init(false),
    cl::desc("Emit a seeded local symbol at the start of every split chunk"));
// Ground truth for the measurement: (function, chunk index, symbol) per chunk.
// The file is appended to, so several TUs can share one sidecar.
static cl::opt<std::string> SplitSymbolsSidecar(
    "split-symbols-sidecar", cl::Hidden, cl::init(""),
    cl::desc("Append the split-chunk -> symbol map to this file"));

// ---- S2 computed branches ------------------------------------------------
// The split leaves the edges between chunks followable: `b` carries a
// displacement, and the ADRP+ADD+BR the split emits elsewhere names the
// target's own block symbol.  Either way a recursive-descent disassembler
// rebuilds the original CFG without knowing how the blocks were laid out.
// With this flag a selected edge is turned into
//
//     adrp  xB, <table>@PAGE
//     add   xB, xB, <table>@PAGEOFF
//     ldrsw xT, [xB, #idx]      ; entry = (target - table) + key
//     sub   xT, xT, #key
//     add   xB, xT, xB
//     br    xB
//
// so the successor exists only as a data word in __TEXT,__const and the code
// carries no displacement and no reference to the target block.  The table
// stores *table-relative* offsets, not addresses: it needs no rebase (it is
// slide-safe) and its raw contents are not the final delta until the
// per-build key is subtracted.  Off by default.
static cl::opt<bool> ComputedBranches(
    "computed-branches", cl::Hidden, cl::init(false),
    cl::desc("Turn split cross-chunk edges into table-driven computed branches"));
// (function, edge kind, source block, target block, table index) per edge, plus
// the refusals, so the measurement does not have to infer them from the binary.
static cl::opt<std::string> ComputedBranchesSidecar(
    "computed-branches-sidecar", cl::Hidden, cl::init(""),
    cl::desc("Append the computed-branch edge map to this file"));

#define DEBUG_TYPE "aarch64-obfuscation"

namespace {

struct ObfuscateInstrInfo {
  MachineInstr *RawInst;
  std::vector<MCPhysReg> AvailableRegs;
  bool NZCVAvailable;
};

struct ObfuscateOption {
  bool InsertRubbishCode = false;
  bool SplitBasicBlock = false;
};

enum OperandsType {
  NoOperand,
  RegReg,
  RegImm,
  OnlyReg,
  RegShifted,
  MulAccum,
};

static std::set<unsigned> MergedMBBs;

class AArch64RubbishCodePass : public MachineFunctionPass {
public:
  static char ID;

  AArch64RubbishCodePass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "AArch64 Obfuscation"; }

  bool runOnMachineFunction(MachineFunction &MF) override;

  bool checkShouldProcess(MachineFunction &MF, ObfuscateOption &OO);
  void process(MachineFunction &MF, ObfuscateOption &OO);

  void generateObfuscateInfo(MachineFunction &MF,
                             std::vector<ObfuscateInstrInfo> &Items);
  void generateObfuscateInfo(MachineBasicBlock &MBB,
                             std::vector<ObfuscateInstrInfo> &Items);

  void obfuscateDataFlow(MachineFunction &MF);
  void processBasicBlock(MachineBasicBlock &MBB, unsigned Times);
  void generateRubbishCode(ObfuscateInstrInfo &OI);

  bool buildMIWrapper(unsigned Opcode, ObfuscateInstrInfo &OII,
                      OperandsType Ty, std::vector<MCPhysReg> &Regs,
                      bool Is64Bit, bool DefFlag, bool WriteNZCV);

  MCPhysReg getRegisterBySize(bool Is64Bit, std::vector<MCPhysReg> &Regs);

  void replaceMOVri(ObfuscateInstrInfo &OI, int64_t Value, MCPhysReg ResultReg,
                    bool Is64Bit);

  MachineInstr *insertDirtyBytes(MachineInstr *Before,
                                 std::vector<unsigned char> &Data);

  void insertNopInstruction(MachineBasicBlock &MBB, unsigned Num,
                            std::vector<MachineInstr *> &NopInstrs);

  void randomMoveBasicBlock(MachineFunction &MF,
                            std::vector<MachineInstr *> &FixPoint,
                            std::vector<MachineBasicBlock *> &NewBlocks);
  MachineBasicBlock *splitBasicBlock(MachineBasicBlock *MBB,
                                     MachineInstr *Header, MachineInstr *Tail,
                                     std::vector<MachineInstr *> &FixPoint);
  // Spill X16, materialize To with ADRP+ADD, BR X16. SP moves by 16 bytes.
  void emitIndirectBranch(MachineBasicBlock &From, MachineBasicBlock *To,
                          std::vector<MachineInstr *> &FixPoint);
  void emitX16Reload(MachineBasicBlock *To,
                     std::vector<MachineInstr *> &FixPoint);
  void obfuscateControlFlow(MachineFunction &MF);
  bool containsCall(MachineBasicBlock *MBB);

  // S1: one seeded local label per split chunk (see SplitSymbols above).
  void emitChunkSymbols(MachineFunction &MF);
  // Seeded label at the function entry (linkage parity with real symbols).
  std::string emitEntrySymbol(MachineFunction &MF);

  // S2: table-driven edges (see ComputedBranches above).
  unsigned addCbEntry(MachineBasicBlock *To);
  bool pickDeadRegs(MachineBasicBlock &MBB, MachineInstr *Before, unsigned N,
                    std::vector<MCPhysReg> &Out);
  void emitCbSeq(MachineBasicBlock &MBB, MachineBasicBlock::iterator At,
                 MCPhysReg Base, MCPhysReg Tmp, unsigned Idx,
                 std::vector<MachineInstr *> *FixPoint);
  bool isChunkHead(MachineBasicBlock *MBB) const;
  bool crossChunk(MachineBasicBlock *From, MachineBasicBlock *To) const;
  void convertComputedBranches(MachineFunction &MF);
  void emitComputedBranchTable(MachineFunction &MF);

private:
  // Blocks produced by the split, in emission order; emitChunkSymbols labels
  // the first instruction of each one.
  std::vector<MachineBasicBlock *> ChunkBlocks;
  // S2: one target table per function, in table-index order.
  std::vector<MCSymbol *> CbTargets;
  // Layout run each block belongs to: -1 = the un-split head region, otherwise
  // the index of the chunk head that starts the run.  A "cross-chunk edge" is
  // one whose two ends have different ids -- this is the same partition the S1
  // chunk symbols describe, and it is what the split actually breaks.
  std::map<MachineBasicBlock *, int> ChunkId;
  std::string CbTableLabel;
  std::string CbRecords;
  unsigned CbConverted = 0, CbSkipped = 0, CbRefused = 0;
  MachineRegisterInfo *MRI = nullptr;
  const AArch64InstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
  // X16 spill, ADRP+ADD, BR, and the matching reload must stay adjacent.
  // Garbage between them breaks the indirect edge.
  std::set<MachineInstr *> Anchors;

  // Caller-saved general purpose registers that are safe to trash:
  // skip X8 (indirect result), X16/X17 (IP0/IP1 veneer), X18 (platform),
  // X29/X30 (FP/LR). Each 64-bit reg pairs with its Wn 32-bit view.
  std::vector<MCPhysReg> RegListX = {
      AArch64::X0,  AArch64::X1,  AArch64::X2,  AArch64::X3,
      AArch64::X4,  AArch64::X5,  AArch64::X6,  AArch64::X7,
      AArch64::X9,  AArch64::X10, AArch64::X11, AArch64::X12,
      AArch64::X13, AArch64::X14, AArch64::X15};
  std::vector<MCPhysReg> RegListW = {
      AArch64::W0,  AArch64::W1,  AArch64::W2,  AArch64::W3,
      AArch64::W4,  AArch64::W5,  AArch64::W6,  AArch64::W7,
      AArch64::W9,  AArch64::W10, AArch64::W11, AArch64::W12,
      AArch64::W13, AArch64::W14, AArch64::W15};
};
} // end anonymous namespace

char AArch64RubbishCodePass::ID = 0;

INITIALIZE_PASS(AArch64RubbishCodePass, DEBUG_TYPE, DEBUG_TYPE, false, false)

FunctionPass *llvm::createAArch64RubbishCodePassPass() {
  return new AArch64RubbishCodePass();
}

MachineInstr *AArch64RubbishCodePass::insertDirtyBytes(
    MachineInstr *Before, std::vector<unsigned char> &Data) {
  MachineBasicBlock *MBB = Before->getParent();
  std::string AsmStr = ".byte ";
  char Hex[10] = {0};
  bool Tail = false;
  for (unsigned char d : Data) {
    if (Tail)
      AsmStr += ", ";
    sprintf(Hex, "0x%02x", d);
    AsmStr += std::string(Hex);
    Tail = true;
  }
  // Keep the string alive: addExternalSymbol stores the raw pointer, so the
  // bytes must outlive the MachineFunction (X86 version keeps them in Asm).
  char *Persist = new char[AsmStr.size() + 1];
  memcpy(Persist, AsmStr.c_str(), AsmStr.size() + 1);
  return BuildMI(*MBB, *Before, Before->getDebugLoc(),
                 TII->get(AArch64::INLINEASM))
      .addExternalSymbol(Persist)
      .addImm(InlineAsm::Extra_HasSideEffects)
      .getInstr();
}

MCPhysReg AArch64RubbishCodePass::getRegisterBySize(bool Is64Bit,
                                                std::vector<MCPhysReg> &Regs) {
  std::vector<MCPhysReg> Available;
  for (MCPhysReg Reg : Regs) {
    bool RegIs64 = AArch64::GPR64RegClass.contains(Reg);
    if (RegIs64 == Is64Bit) {
      Available.push_back(Reg);
    }
  }
  if (Available.empty())
    return AArch64::NoRegister;
  return Available[obfRand() % Available.size()];
}

// Build a garbage instruction in front of Ptr. WriteNZCV is only true when
// NZCV is live-out free at this point.
bool AArch64RubbishCodePass::buildMIWrapper(unsigned Opcode,
                                        ObfuscateInstrInfo &OII,
                                        OperandsType Ty,
                                        std::vector<MCPhysReg> &Regs,
                                        bool Is64Bit, bool DefFlag,
                                        bool WriteNZCV) {
  MachineInstr *Ptr = OII.RawInst;
  MachineBasicBlock *MBB = Ptr->getParent();
  MachineInstr *Gen = nullptr;

  switch (Ty) {
  case NoOperand:
    Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode)).getInstr();
    return true;

  case MulAccum: {
    // MADD/MSUB Xrrr: Rd = Rn op Rm + Ra. Use XZR as the accumulator.
    MCPhysReg Reg0 = getRegisterBySize(Is64Bit, Regs);
    MCPhysReg Reg1 = getRegisterBySize(Is64Bit, Regs);
    if (Reg0 == AArch64::NoRegister || Reg1 == AArch64::NoRegister)
      return false;
    Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode))
              .addDef(Reg0)
              .addReg(Reg0)
              .addReg(Reg1)
              .addReg(AArch64::XZR)
              .getInstr();
    return true;
  }

  case RegReg: {
    // AArch64 register-form ALU ops are only encodable in their shifted-
    // register (rs) form: Rd, Rn, Rm, imm6. With shift 0 they are the
    // plain Rr equivalents. S-forms (ADDS/SUBS/ANDS) take NZCV as op0.
    MCPhysReg Reg0 = getRegisterBySize(Is64Bit, Regs);
    MCPhysReg Reg1 = getRegisterBySize(Is64Bit, Regs);
    if (Reg0 == AArch64::NoRegister || Reg1 == AArch64::NoRegister)
      return false;
    if (DefFlag) {
      Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode))
                .addDef(Reg0)
                .addReg(Reg0)
                .addReg(Reg1)
                .addImm(0)
                .getInstr();
    } else {
      // S-forms write both Rd and NZCV.
      Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode))
                .addDef(Reg0)
                .addReg(Reg0)
                .addReg(Reg1)
                .addImm(0)
                .getInstr();
    }
    return true;
  }

  case RegImm: {
    MCPhysReg Reg0 = getRegisterBySize(Is64Bit, Regs);
    if (Reg0 == AArch64::NoRegister)
      return false;
    // ADD/SUB imm12: 0..4095 (shift 0). The shifted-imm operand expands to
    // two machine operands: [imm, shift].
    uint64_t Imm = obfRand() % 4096;
    Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode))
              .addDef(Reg0)
              .addReg(Reg0)
              .addImm(Imm)
              .addImm(0)
              .getInstr();
    return true;
  }

  case OnlyReg: {
    MCPhysReg Reg0 = getRegisterBySize(Is64Bit, Regs);
    if (Reg0 == AArch64::NoRegister)
      return false;
    Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode))
              .addDef(Reg0)
              .addReg(Reg0)
              .getInstr();
    return true;
  }

  case RegShifted: {
    // Rs forms: Rd = Rn op Rm, LSL #imm  (shifted register, imm 0..63/31)
    MCPhysReg Reg0 = getRegisterBySize(Is64Bit, Regs);
    MCPhysReg Reg1 = getRegisterBySize(Is64Bit, Regs);
    if (Reg0 == AArch64::NoRegister || Reg1 == AArch64::NoRegister)
      return false;
    uint64_t Shift = obfRand() % (Is64Bit ? 64 : 32);
    Gen = BuildMI(*MBB, *Ptr, Ptr->getDebugLoc(), TII->get(Opcode))
              .addDef(Reg0)
              .addReg(Reg0)
              .addReg(Reg1)
              .addImm(Shift)
              .getInstr();
    return true;
  }
  }
  return false;
}

// Replace "MOV Ri, imm" with a 2-4 instruction equivalent sequence:
//   MOVN/MOVZ + MOVK chains, or MOVZ/MOVN of complementary value.
// Any 64-bit constant can be built with MOVZ/MOVN + up to 3 MOVK.
void AArch64RubbishCodePass::replaceMOVri(ObfuscateInstrInfo &OI, int64_t Value,
                                      MCPhysReg ResultReg, bool Is64Bit) {
  MachineInstr *MI = OI.RawInst;
  MachineBasicBlock *MBB = MI->getParent();
  DebugLoc DL = MI->getDebugLoc();
  unsigned Width = Is64Bit ? 64 : 32;
  uint64_t UVal = (uint64_t)Value & (Is64Bit ? ~0ULL : 0xFFFFFFFFULL);

  unsigned MovZOp = Is64Bit ? AArch64::MOVZXi : AArch64::MOVZWi;
  unsigned MovKOp = Is64Bit ? AArch64::MOVKXi : AArch64::MOVKWi;
  unsigned MovNOp = Is64Bit ? AArch64::MOVNXi : AArch64::MOVNWi;

  // Count nonzero 16-bit chunks.
  unsigned NumChunks = Width / 16;
  unsigned FirstChunk = 0;
  for (unsigned i = 0; i < NumChunks; i++) {
    if (((UVal >> (16 * i)) & 0xFFFF) != 0) {
      FirstChunk = i;
      break;
    }
  }

  // Try MOVN of the complement when it produces a shorter sequence.
  uint64_t Comp = Is64Bit ? ~UVal : (~UVal & 0xFFFFFFFFULL);
  unsigned CompFirst = NumChunks;
  for (unsigned i = 0; i < NumChunks; i++) {
    if (((Comp >> (16 * i)) & 0xFFFF) != 0) {
      CompFirst = i;
      break;
    }
  }

  bool UseNeg = false;
  unsigned Base, BaseChunk;
  uint64_t BaseVal;
  if ((CompFirst < FirstChunk) || FirstChunk == NumChunks) {
    UseNeg = true;
    Base = MovNOp;
    BaseChunk = CompFirst;
    BaseVal = Comp;
  } else {
    Base = MovZOp;
    BaseChunk = FirstChunk;
    BaseVal = UVal;
  }

  if (BaseChunk == NumChunks) {
    // Value is zero.
    BuildMI(*MBB, *MI, DL, TII->get(AArch64::ORRXrr))
        .addDef(ResultReg)
        .addReg(AArch64::XZR)
        .addReg(AArch64::XZR)
        .getInstr();
    return;
  }

  uint64_t BaseImm = (BaseVal >> (16 * BaseChunk)) & 0xFFFF;
  unsigned Hw = BaseChunk;
  BuildMI(*MBB, *MI, DL, TII->get(Base))
      .addDef(ResultReg)
      .addImm(BaseImm)
      .addImm(Hw << 16)
      .getInstr();
  for (unsigned i = BaseChunk + 1; i < NumChunks; i++) {
    uint64_t Chunk = (BaseVal >> (16 * i)) & 0xFFFF;
    if (Chunk == 0 && Base == MovZOp)
      continue;
    if (Chunk == 0xFFFF && Base == MovNOp)
      continue;
    BuildMI(*MBB, *MI, DL, TII->get(MovKOp))
        .addDef(ResultReg)
        .addReg(ResultReg)
        .addImm(Chunk)
        .addImm(i << 16)
        .getInstr();
  }
}

static bool containsFrameDestroy(MachineBasicBlock *MBB) {
  for (MachineInstr &MI : *MBB)
    if (MI.getFlag(MachineInstr::FrameDestroy))
      return true;
  return false;
}

bool AArch64RubbishCodePass::containsCall(MachineBasicBlock *MBB) {
  for (MachineInstr &MI : *MBB) {
    if (MI.isCall())
      return true;
  }
  return false;
}

// Spill X16 with a 16-byte pre-indexed store, materialize the block address
// in X16, and BR X16. The target block must start with emitX16Reload.
void AArch64RubbishCodePass::emitIndirectBranch(
    MachineBasicBlock &From, MachineBasicBlock *To,
    std::vector<MachineInstr *> &FixPoint) {
  DebugLoc DL;
  MachineBasicBlock::iterator At = From.end();
  if (ComputedBranches) {
    // Two scratch registers, so the spill/reload pair covers X16 and X17.
    MachineInstr *Spill =
        BuildMI(From, At, DL, TII->get(AArch64::STPXpre))
            .addReg(AArch64::SP, RegState::Define)
            .addReg(AArch64::X16)
            .addReg(AArch64::X17)
            .addReg(AArch64::SP)
            .addImm(-16)
            .getInstr();
    Anchors.insert(Spill);
    FixPoint.push_back(Spill);
    emitCbSeq(From, At, AArch64::X16, AArch64::X17, addCbEntry(To), &FixPoint);
    To->setMachineBlockAddressTaken();
    To->setLabelMustBeEmitted();
    return;
  }
  MachineInstr *Save =
      BuildMI(From, At, DL, TII->get(AArch64::STRXpre))
          .addReg(AArch64::SP, RegState::Define)
          .addReg(AArch64::X16)
          .addReg(AArch64::SP)
          .addImm(-16)
          .getInstr();
  MCSymbol *Sym = To->getSymbol();
  MachineInstr *Adrp =
      BuildMI(From, At, DL, TII->get(AArch64::ADRP))
          .addReg(AArch64::X16, RegState::Define)
          .addSym(Sym, AArch64II::MO_PAGE)
          .getInstr();
  MachineInstr *Add =
      BuildMI(From, At, DL, TII->get(AArch64::ADDXri))
          .addReg(AArch64::X16, RegState::Define)
          .addReg(AArch64::X16)
          .addSym(Sym, static_cast<unsigned char>(AArch64II::MO_PAGEOFF |
                                                  AArch64II::MO_NC))
          .addImm(0)
          .getInstr();
  MachineInstr *Br = BuildMI(From, At, DL, TII->get(AArch64::BR))
                         .addReg(AArch64::X16)
                         .getInstr();
  for (MachineInstr *I : {Save, Adrp, Add, Br}) {
    Anchors.insert(I);
    FixPoint.push_back(I);
  }
  To->setMachineBlockAddressTaken();
  To->setLabelMustBeEmitted();
}

void AArch64RubbishCodePass::emitX16Reload(
    MachineBasicBlock *To, std::vector<MachineInstr *> &FixPoint) {
  MachineInstr *Reload;
  if (ComputedBranches) {
    // The computed-branch sequence clobbers X16 and X17, and emitIndirectBranch
    // spilled both as a pair.
    Reload = BuildMI(*To, To->begin(), DebugLoc(), TII->get(AArch64::LDPXpost))
                 .addReg(AArch64::SP, RegState::Define)
                 .addReg(AArch64::X16, RegState::Define)
                 .addReg(AArch64::X17, RegState::Define)
                 .addReg(AArch64::SP)
                 .addImm(16)
                 .getInstr();
  } else {
    Reload = BuildMI(*To, To->begin(), DebugLoc(), TII->get(AArch64::LDRXpost))
                 .addReg(AArch64::SP, RegState::Define)
                 .addReg(AArch64::X16, RegState::Define)
                 .addReg(AArch64::SP)
                 .addImm(16)
                 .getInstr();
  }
  Anchors.insert(Reload);
  FixPoint.push_back(Reload);
}

// ---- S2: table-driven cross-chunk edges ----------------------------------

// One key for the whole build, 12 bits so `sub #key` stays a single
// instruction.  It only has to keep the table's raw contents from being the
// final delta; see reports/SPLIT-COMPUTED-BRANCHES.md for what that is worth.
static unsigned cbTableKey() {
  static unsigned K = [] {
    uint64_t H = mixNameHash(splitNameSeed(), 0x53324b4559ULL); // "S2KEY"
    return unsigned((H >> 17) % 4095) + 1;
  }();
  return K;
}

// Temp label (leading 'L' keeps it out of the nlist) for this function's table.
static std::string makeCbTableLabel(StringRef Module, StringRef Fn) {
  static unsigned Salt = 0;
  uint64_t H =
      mixNameHash(splitNameSeed(), (uint64_t)(size_t)hash_value(Module));
  H = mixNameHash(H, (uint64_t)(size_t)hash_value(Fn));
  H = mixNameHash(H, ++Salt);
  char Buf[40];
  snprintf(Buf, sizeof(Buf), "L__pcb%012llx",
           (unsigned long long)((H >> 16) & 0xffffffffffffULL));
  return std::string(Buf);
}

unsigned AArch64RubbishCodePass::addCbEntry(MachineBasicBlock *To) {
  MCSymbol *Sym = To->getSymbol();
  To->setMachineBlockAddressTaken();
  To->setLabelMustBeEmitted();
  CbTargets.push_back(Sym);
  return CbTargets.size() - 1;
}

bool AArch64RubbishCodePass::isChunkHead(MachineBasicBlock *MBB) const {
  for (MachineBasicBlock *C : ChunkBlocks)
    if (C == MBB)
      return true;
  return false;
}

bool AArch64RubbishCodePass::crossChunk(MachineBasicBlock *From,
                                        MachineBasicBlock *To) const {
  auto A = ChunkId.find(From), B = ChunkId.find(To);
  if (A == ChunkId.end() || B == ChunkId.end())
    return false;
  return A->second != B->second;
}

// Pick N general-purpose registers that are dead on every outgoing path at
// Before.  Caller-saved only (RegListX skips x8/x16/x17/x18/x29/x30) and the
// live-out set is the union over the successors' live-ins, so a register that
// is live into *either* arm of a conditional is never handed out.
bool AArch64RubbishCodePass::pickDeadRegs(MachineBasicBlock &MBB,
                                          MachineInstr *Before, unsigned N,
                                          std::vector<MCPhysReg> &Out) {
  LivePhysRegs LiveRegs;
  LiveRegs.init(*MBB.getParent()->getSubtarget().getRegisterInfo());
  LiveRegs.addLiveOutsNoPristines(MBB);
  for (auto I = MBB.rbegin(), E = MBB.rend(); I != E; ++I) {
    if (&*I == Before)
      break;
    LiveRegs.stepBackward(*I);
  }
  if (Before != MBB.end())
    LiveRegs.stepBackward(*Before);
  for (MCPhysReg Reg : RegListX) {
    if (Out.size() == N)
      break;
    if (LiveRegs.available(*MRI, Reg))
      Out.push_back(Reg);
  }
  return Out.size() == N;
}

// adrp/add <table>; ldrsw; sub #key; add base; br.  Clobbers Base and Tmp.
void AArch64RubbishCodePass::emitCbSeq(MachineBasicBlock &MBB,
                                       MachineBasicBlock::iterator At,
                                       MCPhysReg Base, MCPhysReg Tmp,
                                       unsigned Idx,
                                       std::vector<MachineInstr *> *FixPoint) {
  DebugLoc DL;
  MCSymbol *Tbl =
      MBB.getParent()->getMMI().getContext().getOrCreateSymbol(CbTableLabel);
  auto Add = [&](MachineInstr *MI) {
    Anchors.insert(MI);
    if (FixPoint)
      FixPoint->push_back(MI);
  };
  Add(BuildMI(MBB, At, DL, TII->get(AArch64::ADRP))
          .addReg(Base, RegState::Define)
          .addSym(Tbl, AArch64II::MO_PAGE)
          .getInstr());
  Add(BuildMI(MBB, At, DL, TII->get(AArch64::ADDXri))
          .addReg(Base, RegState::Define)
          .addReg(Base)
          .addSym(Tbl, static_cast<unsigned char>(AArch64II::MO_PAGEOFF |
                                                 AArch64II::MO_NC))
          .addImm(0)
          .getInstr());
  // The uimm12s4 operand holds the byte offset divided by 4.
  Add(BuildMI(MBB, At, DL, TII->get(AArch64::LDRSWui))
          .addReg(Tmp, RegState::Define)
          .addReg(Base)
          .addImm((int64_t)Idx)
          .getInstr());
  Add(BuildMI(MBB, At, DL, TII->get(AArch64::SUBXri))
          .addReg(Tmp, RegState::Define)
          .addReg(Tmp)
          .addImm((int64_t)cbTableKey())
          .addImm(0)
          .getInstr());
  // Only the shifted-register form has an encoding; shift 0 is the plain add.
  Add(BuildMI(MBB, At, DL, TII->get(AArch64::ADDXrs))
          .addReg(Base, RegState::Define)
          .addReg(Tmp)
          .addReg(Base)
          .addImm(0)
          .getInstr());
  Add(BuildMI(MBB, At, DL, TII->get(AArch64::BR)).addReg(Base).getInstr());
}

// ARMRC_CB_ALL=1 widens the selection from "crosses the split" to "every
// direct branch in the function"; it only exists to measure the two settings.
static bool cbAllEdges() {
  static bool All = getenv("ARMRC_CB_ALL") != nullptr;
  return All;
}

// Rewrite the selected edges of one function.  Selection: an edge whose target
// is a split chunk head (i.e. an edge that crosses the split), never into the
// entry block (the prologue keeps exactly one visible entry), and never into a
// chunk that already starts with the split's SP reload.
void AArch64RubbishCodePass::convertComputedBranches(MachineFunction &MF) {
  if (!ComputedBranches)
    return;
  std::string FnName = MF.getFunction().getName().str();
  auto Refuse = [&](MachineBasicBlock &MBB, MachineBasicBlock *To,
                    const char *Why) {
    ++CbRefused;
    CbRecords += std::string("refused\t") + FnName + "\t" + Why + "\t" +
                 std::to_string(MBB.getNumber()) + "\t" +
                 std::to_string(To->getNumber()) + "\n";
  };
  ChunkId.clear();
  {
    int Cur = -1, Next = 0;
    for (MachineBasicBlock &B : MF) {
      if (isChunkHead(&B))
        Cur = Next++;
      ChunkId[&B] = Cur;
    }
  }
  auto StartsWithSpillReload = [](MachineBasicBlock *MBB) {
    if (MBB->empty())
      return false;
    unsigned Opc = MBB->front().getOpcode();
    return Opc == AArch64::LDRXpost || Opc == AArch64::LDPXpost;
  };

  for (MachineBasicBlock &MBB : MF) {
    MachineBasicBlock::iterator TermIt = MBB.getFirstTerminator();
    if (TermIt == MBB.end())
      continue;
    MachineInstr *Term = &*TermIt;
    unsigned Opc = Term->getOpcode();
    // Exactly one terminator, at the end: anything else (BR sequences, blocks
    // that still carry a dead `B` after a Bcc) is left alone, because rewriting
    // the first of several terminators would leave unreachable branch code.
    {
      unsigned NumTerms = 0;
      bool Last = (Term->getNextNode() == nullptr);
      for (MachineInstr &I : MBB)
        if (I.isTerminator())
          ++NumTerms;
      if (NumTerms != 1 || !Last) {
        ++CbRefused;
        CbRecords += "refused\t" + FnName + "\tterm-chain\t" +
                     std::to_string(MBB.getNumber()) + "\t-\n";
        continue;
      }
    }
    if (getenv("ARMRC_CB_DEBUG")) {
      errs() << "[cb] mbb=" << MBB.getNumber() << " term="
             << TII->getName(Opc) << " ops=" << Term->getNumOperands()
             << " succ=" << MBB.succ_size() << " chunk="
             << (isChunkHead(&MBB) ? 1 : 0) << " id="
             << ChunkId[&MBB] << " end=";
      for (MachineBasicBlock *S : MBB.successors())
        errs() << S->getNumber() << ",";
      errs() << "\n";
    }

    // --- unconditional ---
    if (Opc == AArch64::B) {
      if (Term->getNumOperands() != 1 || !Term->getOperand(0).isMBB())
        continue;
      MachineBasicBlock *To = Term->getOperand(0).getMBB();
      if (!crossChunk(&MBB, To) && !cbAllEdges()) {
        Refuse(MBB, To, "not-cross-chunk");
        continue;
      }
      if (To->isEntryBlock()) {
        Refuse(MBB, To, "entry-block");
        continue;
      }
      if (StartsWithSpillReload(To)) {
        Refuse(MBB, To, "sp-reload-target");
        continue;
      }
      std::vector<MCPhysReg> R;
      if (!pickDeadRegs(MBB, Term, 2, R)) {
        ++CbSkipped;
        CbRecords += "skip\t" + FnName + "\tregs\t" +
                     std::to_string(MBB.getNumber()) + "\t" +
                     std::to_string(To->getNumber()) + "\n";
        continue;
      }
      unsigned Idx = addCbEntry(To);
      Term->eraseFromParent();
      emitCbSeq(MBB, MBB.end(), R[0], R[1], Idx, nullptr);
      ++CbConverted;
      CbRecords += "cb\t" + FnName + "\tb\t" + std::to_string(MBB.getNumber()) +
                   "\t" + std::to_string(To->getNumber()) + "\t" +
                   std::to_string(Idx) + "\n";
      continue;
    }

    // --- conditional ---
    unsigned CCOp = 0;   // instruction that materializes the condition in NZCV
    unsigned Cond = AArch64CC::EQ;
    MCPhysReg TestReg = AArch64::NoRegister;
    int64_t TestMask = 0;
    bool IsTest = false;
    // AArch64 branch instructions carry a `bb` operand plus whatever the asm
    // printer needs; Bcc has three operands (cond, bb, and a symbol slot), so
    // the target is found by type rather than by position.
    MachineBasicBlock *Taken = nullptr;
    for (unsigned i = 0; i < Term->getNumOperands(); i++)
      if (Term->getOperand(i).isMBB()) {
        Taken = Term->getOperand(i).getMBB();
        break;
      }
    if (!Taken)
      continue;
    switch (Opc) {
    case AArch64::CBZW:
    case AArch64::CBZX:
    case AArch64::CBNZW:
    case AArch64::CBNZX: {
      bool Is64 = (Opc == AArch64::CBZX || Opc == AArch64::CBNZX);
      bool IsNz = (Opc == AArch64::CBNZW || Opc == AArch64::CBNZX);
      if (!Term->getOperand(0).isReg())
        continue;
      CCOp = Is64 ? AArch64::SUBSXri : AArch64::SUBSWri;
      TestReg = Term->getOperand(0).getReg();
      Cond = IsNz ? AArch64CC::NE : AArch64CC::EQ;
      break;
    }
    case AArch64::TBZW:
    case AArch64::TBZX:
    case AArch64::TBNZW:
    case AArch64::TBNZX: {
      bool Is64 = (Opc == AArch64::TBZX || Opc == AArch64::TBNZX);
      bool IsNz = (Opc == AArch64::TBNZW || Opc == AArch64::TBNZX);
      if (!Term->getOperand(0).isReg() || !Term->getOperand(1).isImm())
        continue;
      unsigned Bit = (unsigned)Term->getOperand(1).getImm();
      if (Bit >= (Is64 ? 64u : 32u))
        continue;
      CCOp = Is64 ? AArch64::ANDSXri : AArch64::ANDSWri;
      TestReg = Term->getOperand(0).getReg();
      TestMask = 1LL << Bit;
      IsTest = true;
      Cond = IsNz ? AArch64CC::NE : AArch64CC::EQ;
      break;
    }
    case AArch64::Bcc: {
      if (!Term->getOperand(0).isImm())
        continue;
      Cond = (unsigned)Term->getOperand(0).getImm();
      break;
    }
    default:
      continue;
    }
    // The second arm is the block laid out next, not a successor-list entry:
    // the split moves blocks around and edits successor lists by hand, so the
    // recorded CFG is not what the assembler emits.  A conditional terminator
    // falls through to whatever follows it in layout order.
    MachineBasicBlock *Fall = nullptr;
    if (MachineFunction::iterator FallIt = std::next(MBB.getIterator());
        FallIt != MF.end())
      Fall = &*FallIt;
    if (!Fall) {
      Refuse(MBB, Taken, "no-fallthrough");
      continue;
    }
    if (!crossChunk(&MBB, Taken) && !crossChunk(&MBB, Fall) && !cbAllEdges()) {
      Refuse(MBB, Taken, "not-cross-chunk");
      continue;
    }
    if (Taken->isEntryBlock() || Fall->isEntryBlock()) {
      Refuse(MBB, Taken->isEntryBlock() ? Taken : Fall, "entry-block");
      continue;
    }
    if (StartsWithSpillReload(Taken) || StartsWithSpillReload(Fall)) {
      Refuse(MBB, Taken, "sp-reload-target");
      continue;
    }
    std::vector<MCPhysReg> R;
    if (!pickDeadRegs(MBB, Term, 3, R)) {
      ++CbSkipped;
      CbRecords += "skip\t" + FnName + "\tregs-cond\t" +
                   std::to_string(MBB.getNumber()) + "\t" +
                   std::to_string(Taken->getNumber()) + "\n";
      continue;
    }
    unsigned IdxT = addCbEntry(Taken);
    unsigned IdxF = addCbEntry(Fall);
    DebugLoc DL = Term->getDebugLoc();
    if (CCOp) {
      if (IsTest)
        BuildMI(MBB, TermIt, DL, TII->get(CCOp))
            .addReg(AArch64::XZR, RegState::Define)
            .addReg(TestReg)
            .addImm(TestMask)
            .addImm(0);
      else
        BuildMI(MBB, TermIt, DL, TII->get(CCOp))
            .addReg(AArch64::XZR, RegState::Define)
            .addReg(TestReg)
            .addImm(0)
            .addImm(0);
    }
    // Both arms become data: two loads, one csel, one br.
    MCSymbol *Tbl = MF.getMMI().getContext().getOrCreateSymbol(CbTableLabel);
    MCPhysReg Base = R[0], Tmp = R[1], Aux = R[2];
    auto Add = [&](MachineInstr *MI) { Anchors.insert(MI); };
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::ADRP))
            .addReg(Base, RegState::Define)
            .addSym(Tbl, AArch64II::MO_PAGE)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::ADDXri))
            .addReg(Base, RegState::Define)
            .addReg(Base)
            .addSym(Tbl, static_cast<unsigned char>(AArch64II::MO_PAGEOFF |
                                                   AArch64II::MO_NC))
            .addImm(0)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::LDRSWui))
            .addReg(Tmp, RegState::Define)
            .addReg(Base)
            .addImm((int64_t)IdxT)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::LDRSWui))
            .addReg(Aux, RegState::Define)
            .addReg(Base)
            .addImm((int64_t)IdxF)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::SUBXri))
            .addReg(Tmp, RegState::Define)
            .addReg(Tmp)
            .addImm((int64_t)cbTableKey())
            .addImm(0)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::SUBXri))
            .addReg(Aux, RegState::Define)
            .addReg(Aux)
            .addImm((int64_t)cbTableKey())
            .addImm(0)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::CSELXr))
            .addReg(Tmp, RegState::Define)
            .addReg(Tmp)
            .addReg(Aux)
            .addImm((int64_t)Cond)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::ADDXrs))
            .addReg(Base, RegState::Define)
            .addReg(Tmp)
            .addReg(Base)
            .addImm(0)
            .getInstr());
    Add(BuildMI(MBB, TermIt, DL, TII->get(AArch64::BR)).addReg(Base).getInstr());
    Term->eraseFromParent();
    ++CbConverted;
    CbRecords += "cb\t" + FnName + "\tcond\t" +
                 std::to_string(MBB.getNumber()) + "\t" +
                 std::to_string(Taken->getNumber()) + "\t" +
                 std::to_string(IdxT) + "\n";
    CbRecords += "cb\t" + FnName + "\tcond-fall\t" +
                 std::to_string(MBB.getNumber()) + "\t" +
                 std::to_string(Fall->getNumber()) + "\t" +
                 std::to_string(IdxF) + "\n";
  }
}

// One table per function in __TEXT,__const:
//   .long <chunk symbol> - <table> + <key>
// Table-relative, so the entry needs no rebase and no slide fixup, and it is
// not the final delta until the key is subtracted.  Emitted as inline asm at
// the top of the function: the directives switch the section and switch it
// back, so no bytes land in __text.
void AArch64RubbishCodePass::emitComputedBranchTable(MachineFunction &MF) {
  if (!ComputedBranches || CbTargets.empty())
    return;
  if (!MF.getTarget().getTargetTriple().isOSBinFormatMachO()) {
    static bool Warned = false;
    if (!Warned) {
      Warned = true;
      errs() << "[computed-branches] only implemented for Mach-O, skipped\n";
    }
    return;
  }
  unsigned Key = cbTableKey();
  std::string S = ".section __TEXT,__const\n.p2align 2\n";
  S += CbTableLabel + ":\n";
  for (MCSymbol *T : CbTargets) {
    S += ".long " + T->getName().str() + " - " + CbTableLabel + " + " +
         std::to_string(Key) + "\n";
  }
  S += ".section __TEXT,__text,regular,pure_instructions\n";
  char *Persist = new char[S.size() + 1];
  memcpy(Persist, S.c_str(), S.size() + 1);
  MachineBasicBlock &Entry = MF.front();
  BuildMI(Entry, Entry.begin(), nullptr, TII->get(AArch64::INLINEASM))
      .addExternalSymbol(Persist)
      .addImm(InlineAsm::Extra_HasSideEffects);
  if (getenv("ARMRC_DEBUG"))
    errs() << "[computed-branches] " << MF.getFunction().getName()
           << " entries=" << CbTargets.size() << " key=" << Key << "\n";
}

// Split MBB between Header and Tail and move the body to the end of the
// function. Executed edges are BR X16 after ADRP+ADD, not direct B, so a
// disassembler cannot follow the boundary. Dirty bytes occupy the layout
// fallthrough of MBB and are never executed. A call or FrameDestroy in the
// body is merged back: a call clobbers the surrounding frame, and
// FrameDestroy must stay with the epilogue.
MachineBasicBlock *
AArch64RubbishCodePass::splitBasicBlock(MachineBasicBlock *MBB,
                                    MachineInstr *Header, MachineInstr *Tail,
                                    std::vector<MachineInstr *> &FixPoint) {
  if (Header->getParent() != MBB || Header->getParent() != Tail->getParent()) {
      return nullptr;
  }

  MachineBasicBlock::iterator SplitPoint(Header);
  MachineBasicBlock::iterator EndPoint(Tail);
  bool Available = false;
  while (SplitPoint != MBB->end()) {
    if (SplitPoint == EndPoint) {
      Available = true;
      break;
    }
    SplitPoint++;
  }
  if (!Available || ++EndPoint == MBB->end()) {
    return nullptr;
  }
  MachineInstr *Point1 = Header, *Point2 = Tail;
  MachineFunction *MF = MBB->getParent();
  if (Header == Tail) {
    MachineBasicBlock::iterator It(Header);
    MachineInstr &NextInstr = *++It;
    Point2 = BuildMI(*MBB, NextInstr, NextInstr.getDebugLoc(),
                     TII->get(AArch64::HINT))
                 .addImm(0)
                 .getInstr();
  }

  MachineBasicBlock *Body = MBB->splitAt(*Point1, true, nullptr);
  if (Body == MBB || Body == nullptr ||
      Point2->getParent() != Body ||
      Point2->getFlag(MachineInstr::FrameSetup) ||
      Point2->getFlag(MachineInstr::FrameDestroy) ||
      Body->size() < 4) {
    // Degenerate first/second split — merge back and abort.
    if (Body != nullptr && Body != MBB) {
      MBB->splice(MBB->end(), Body, Body->begin(), Body->end());
      // Body 的 successors 先转回 MBB, 再删边/删块 (否则悬空边 → 后续 split 崩)
      while (Body->succ_size() != 0) {
        MachineBasicBlock *S = *Body->succ_begin();
        Body->removeSuccessor(S);
        MBB->addSuccessor(S);
      }
      MBB->removeSuccessor(Body);
      MF->deleteMachineBasicBlock(Body);
    }
    return nullptr;
  }
  MachineBasicBlock *End = Body->splitAt(*Point2, true, nullptr);

  if (containsCall(Body) || containsCall(End) || containsFrameDestroy(Body)) {
    // LR would be clobbered inside the body; abort this split and merge back.
    MBB->splice(MBB->end(), Body, Body->begin(), Body->end());
    MBB->splice(MBB->end(), End, End->begin(), End->end());
    while (Body->succ_size() != 0) {
      MachineBasicBlock *S = *Body->succ_begin();
      Body->removeSuccessor(S);
      MBB->addSuccessor(S);
    }
    while (End->succ_size() != 0) {
      MachineBasicBlock *S = *End->succ_begin();
      End->removeSuccessor(S);
      MBB->addSuccessor(S);
    }
    MergedMBBs.insert(MBB->getNumber());
    Body->eraseFromParent();
    End->eraseFromParent();
    if (Header == Tail) {
      Point2->eraseFromParent();
    }
    return nullptr;
  }

  // X16 is allocatable, so spill it before the branch and reload at each
  // target. The slot is 16 bytes, so SP stays 16-byte aligned.
  emitX16Reload(Body, FixPoint);
  emitX16Reload(End, FixPoint);
  // MBB -> Body is the executed edge. MBB -> End replaces the old dead
  // direct B End so that edge is not a direct branch either. Body -> End
  // is the other executed edge.
  emitIndirectBranch(*MBB, Body, FixPoint);
  emitIndirectBranch(*MBB, End, FixPoint);
  emitIndirectBranch(*Body, End, FixPoint);

  // RubbishSize must be a multiple of 4 (AArch64 instructions are 4-byte
  // aligned). The bytes are never executed; BR X16 skips over them.
  unsigned RubbishSize = ((obfRand() % 30 + 20) * 4) & 0xFFC;
  if (getenv("ARMRC_NO_DIRTY"))
    RubbishSize = 0;

  // Place the garbage in MBB's layout fallthrough. Body is moved to the
  // function end, so the executed BR X16 jumps over this block.
  MachineBasicBlock *DirtyBB = MF->CreateMachineBasicBlock();
  MF->insert(MachineFunction::iterator(Body), DirtyBB);
  MachineInstr *Trap =
      BuildMI(*DirtyBB, DirtyBB->end(), nullptr, TII->get(AArch64::BRK))
          .addImm(1)
          .getInstr();
  if (RubbishSize) {
    std::vector<unsigned char> RandBytes;
    RandBytes.reserve(RubbishSize);
    for (unsigned i = 0; i < RubbishSize; i++)
      RandBytes.push_back(static_cast<unsigned char>(obfRand() & 0xff));
    insertDirtyBytes(Trap, RandBytes);
  }
  DirtyBB->setMachineBlockAddressTaken();
  DirtyBB->setLabelMustBeEmitted();

  Body->moveBefore(&*MF->end());
  // S1: both halves of the split are chunks; the head stays with MBB and keeps
  // the real function symbol, so only Body and End are candidates.  S2 needs
  // the same set even when S1 is off: it is the set of cross-chunk edges.
  if (SplitSymbols || ComputedBranches) {
    ChunkBlocks.push_back(Body);
    ChunkBlocks.push_back(End);
  }
  if (getenv("ARMRC_DEBUG"))
    errs() << "[ARMRC] mbb=" << MBB->getNumber() << " body=" << Body->getNumber()
           << " end=" << End->getNumber() << " dirty=" << DirtyBB->getNumber()
           << "\n";

  if (Header == Tail) {
    Point2->eraseFromParent();
  }
  return Body;
}

void AArch64RubbishCodePass::insertNopInstruction(
    MachineBasicBlock &MBB, unsigned Num, std::vector<MachineInstr *> &NopInstrs) {
  while (Num--) {
    for (MachineInstr &MI : MBB) {
      MachineInstr *Nop =
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(AArch64::HINT))
              .addImm(0)
              .getInstr();
      NopInstrs.push_back(Nop);
    }
  }
}

void AArch64RubbishCodePass::randomMoveBasicBlock(
    MachineFunction &MF, std::vector<MachineInstr *> &FixPoint,
    std::vector<MachineBasicBlock *> &NewBlocks) {
  std::vector<MachineBasicBlock *> WorkList, MoveList;
  for (MachineBasicBlock &MBB : MF) {
    WorkList.push_back(&MBB);
  }
  for (MachineBasicBlock *MBB : WorkList) {
    MachineBasicBlock *CurBB = MBB;
    unsigned Counter = 0;
    MachineBasicBlock::iterator Iter = CurBB->begin();
    while (Iter != CurBB->end() && Iter != CurBB->getFirstTerminator()) {
      if (Counter > 6 && std::find(FixPoint.begin(), FixPoint.end(), &*Iter) ==
                             FixPoint.end()) {
        if (Iter->getFlag(MachineInstr::FrameSetup) ||
            Iter->getFlag(MachineInstr::FrameDestroy) || CurBB->size() < 6) {
          Iter++;
          continue;
        }
        MachineBasicBlock *NewBB = CurBB->splitAt(*Iter, true, nullptr);
        if (NewBB == CurBB) {
          break;
        }
        NewBlocks.push_back(NewBB);
        BuildMI(*CurBB, CurBB->end(), nullptr, TII->get(AArch64::B))
            .addMBB(NewBB);
        if (NewBB->getFirstTerminator() != NewBB->end()) {
          MachineInstr &MI = *NewBB->getFirstTerminator();
          if (MI.isUnconditionalBranch()) {
            MoveList.push_back(NewBB);
          }
        }
        CurBB = NewBB;
        Iter = CurBB->begin();
        Counter = 0;
      } else {
        Iter++, Counter++;
      }
    }
  }

  for (MachineBasicBlock *MBB : MoveList) {
    if (MBB == &MF.front()) {
      continue;
    }
    MachineBasicBlock *Before = MoveList[obfRand() % MoveList.size()];
    if (Before != MBB) {
      MBB->moveBefore(Before);
    }
  }
}

void AArch64RubbishCodePass::generateRubbishCode(ObfuscateInstrInfo &OI) {
  MachineInstr *Ptr = OI.RawInst;
  std::vector<MCPhysReg> &AvailableRegs = OI.AvailableRegs;
  std::vector<MCPhysReg> CommonX(RegListX.begin(), RegListX.end());
  std::vector<MCPhysReg> CommonW(RegListW.begin(), RegListW.end());

  struct RubbishDesc {
    unsigned Opcode;
    OperandsType Ty;
    bool Is64Bit;
    bool Def;   // writes a register (needs AvailableRegs)
    bool Flags; // writes NZCV (needs NZCVAvailable)
  };

  static const std::vector<RubbishDesc> Descs = {
      // Not writing NZCV (safe anywhere):
      {AArch64::ADDXrs, RegReg, true, true, false},
      {AArch64::ADDWrs, RegReg, false, true, false},
      {AArch64::SUBXrs, RegReg, true, true, false},
      {AArch64::SUBWrs, RegReg, false, true, false},
      {AArch64::ORRXrs, RegReg, true, true, false},
      {AArch64::ORRWrs, RegReg, false, true, false},
      {AArch64::ANDXrs, RegReg, true, true, false},
      {AArch64::ANDWrs, RegReg, false, true, false},
      {AArch64::EORXrs, RegReg, true, true, false},
      {AArch64::EORWrs, RegReg, false, true, false},
      {AArch64::BICXrs, RegReg, true, true, false},
      {AArch64::ADDXri, RegImm, true, true, false},
      {AArch64::ADDWri, RegImm, false, true, false},
      {AArch64::SUBXri, RegImm, true, true, false},
      {AArch64::SUBWri, RegImm, false, true, false},
      {AArch64::ADDXrs, RegShifted, true, true, false},
      {AArch64::SUBXrs, RegShifted, true, true, false},
      {AArch64::LSLVXr, OnlyReg, true, true, false},
      {AArch64::LSLVWr, OnlyReg, false, true, false},
      {AArch64::LSRVXr, OnlyReg, true, true, false},
      {AArch64::LSRVWr, OnlyReg, false, true, false},
      {AArch64::ASRVXr, OnlyReg, true, true, false},
      {AArch64::ASRVWr, OnlyReg, false, true, false},
      {AArch64::RORVXr, OnlyReg, true, true, false},
      {AArch64::RORVWr, OnlyReg, false, true, false},
      {AArch64::UDIVXr, OnlyReg, true, true, false},
      {AArch64::UDIVWr, OnlyReg, false, true, false},
      {AArch64::SDIVXr, OnlyReg, true, true, false},
      {AArch64::SDIVWr, OnlyReg, false, true, false},
      {AArch64::MADDXrrr, MulAccum, true, true, false},
      {AArch64::MSUBXrrr, MulAccum, true, true, false},
      {AArch64::SBFMXri, RegImm, true, true, false},
      {AArch64::UBFMXri, RegImm, true, true, false},
      // Writing NZCV (only when NZCV is dead):
      {AArch64::ADDSXrs, RegReg, true, false, true},
      {AArch64::ADDSWrs, RegReg, false, false, true},
      {AArch64::SUBSXrs, RegReg, true, false, true},
      {AArch64::SUBSWrs, RegReg, false, false, true},
      {AArch64::ANDSXrs, RegReg, true, false, true},
      {AArch64::ANDSWrs, RegReg, false, false, true},
      {AArch64::ADDSXri, RegImm, true, false, true},
      {AArch64::SUBSXri, RegImm, true, false, true},
  };

  const RubbishDesc *Sel = nullptr;
  unsigned Tries = 32;
  if (const char *Only = getenv("ARMRC_ONLY_OP")) {
    unsigned want = (unsigned)atoi(Only);
    for (const RubbishDesc &D : Descs)
      if (D.Opcode == want) { Sel = &D; break; }
    if (Sel) {
      buildMIWrapper(Sel->Opcode, OI, Sel->Ty,
                     Sel->Def ? AvailableRegs : CommonX, Sel->Is64Bit, Sel->Def,
                     Sel->Flags);
      return;
    }
  }
  while (Tries--) {
    const RubbishDesc &D = Descs[obfRand() % Descs.size()];
    if (D.Flags && !OI.NZCVAvailable)
      continue;
    if (D.Def && D.Ty != RegImm && D.Ty != OnlyReg) {
      // For Def forms both operand regs come from AvailableRegs; need at
      // least one matching register.
      bool Has = false;
      for (MCPhysReg R : AvailableRegs) {
        if (AArch64::GPR64RegClass.contains(R) == D.Is64Bit) {
          Has = true;
          break;
        }
      }
      if (!Has)
        continue;
    }
    Sel = &D;
    break;
  }
  if (!Sel)
    return;

  buildMIWrapper(Sel->Opcode, OI, Sel->Ty, AvailableRegs, Sel->Is64Bit,
                 Sel->Def, Sel->Flags);
}

void AArch64RubbishCodePass::generateObfuscateInfo(
    MachineFunction &MF, std::vector<ObfuscateInstrInfo> &Items) {
  for (MachineBasicBlock &MBB : MF) {
    generateObfuscateInfo(MBB, Items);
  }
}

void AArch64RubbishCodePass::generateObfuscateInfo(
    MachineBasicBlock &MBB, std::vector<ObfuscateInstrInfo> &Items) {
  LivePhysRegs LiveRegs;
  MachineFunction *MF = MBB.getParent();
  LiveRegs.init(*MBB.getParent()->getSubtarget().getRegisterInfo());
  LiveRegs.addLiveOutsNoPristines(MBB);
  for (auto I = MBB.rbegin(), E = MBB.rend(); I != E; ++I) {
    ObfuscateInstrInfo Info;
    MachineInstr *Instr = &*I;
    Info.RawInst = Instr;
    LiveRegs.stepBackward(*I);

    std::vector<MCPhysReg> AllRegs;
    AllRegs.reserve(RegListX.size() + RegListW.size());
    AllRegs.insert(AllRegs.end(), RegListX.begin(), RegListX.end());
    AllRegs.insert(AllRegs.end(), RegListW.begin(), RegListW.end());
    for (MCPhysReg Reg : AllRegs) {
      if (LiveRegs.available(*MRI, Reg)) {
        Info.AvailableRegs.push_back(Reg);
      }
    }
    Info.NZCVAvailable = LiveRegs.available(*MRI, AArch64::NZCV);
    Items.push_back(Info);
  }
}

void AArch64RubbishCodePass::processBasicBlock(MachineBasicBlock &MBB,
                                           unsigned Times) {
  // Live-in/out state shifts after every insertion, so liveness is
  // recomputed per instruction instead of being batched.
  for (unsigned i = 0; i < Times; i++) {
    for (MachineInstr &Target : MBB) {
      MachineBasicBlock::iterator Start(Target);
      LivePhysRegs LiveRegs;
      LiveRegs.init(*MBB.getParent()->getSubtarget().getRegisterInfo());
      LiveRegs.addLiveOutsNoPristines(MBB);
      for (auto J = MBB.rbegin(); MachineBasicBlock::iterator(J) != Start; ++J)
        LiveRegs.stepBackward(*J);

      ObfuscateInstrInfo Info;
      Info.RawInst = &Target;
      for (MCPhysReg Reg : RegListX)
        if (LiveRegs.available(*MRI, Reg))
          Info.AvailableRegs.push_back(Reg);
      for (MCPhysReg Reg : RegListW)
        if (LiveRegs.available(*MRI, Reg))
          Info.AvailableRegs.push_back(Reg);
      Info.NZCVAvailable = LiveRegs.available(*MRI, AArch64::NZCV);

      if (Target.getOpcode() == AArch64::MOVZXi ||
          Target.getOpcode() == AArch64::MOVZWi) {
        if (Target.getOperand(2).getImm() == 0 && Info.NZCVAvailable) {
          replaceMOVri(Info, Target.getOperand(1).getImm(),
                       Target.getOperand(0).getReg(),
                       Target.getOpcode() == AArch64::MOVZXi);
        }
        continue;
      }
      if (Target.getOpcode() == AArch64::INLINEASM)
        continue;
      // Garbage inserted here lands between Target and its predecessor.
      // If either is an anchor (BL / its landing branch), the call-shaped
      // return path would be broken -- skip.
      if (Anchors.count(&Target))
        continue;
      MachineInstr *Prev = Target.getPrevNode();
      if (Prev && Anchors.count(Prev))
        continue;
      generateRubbishCode(Info);
    }
  }
}

void AArch64RubbishCodePass::obfuscateDataFlow(MachineFunction &MF) {
  for (MachineBasicBlock &MBB : MF) {
    processBasicBlock(MBB, 1);
  }
}

void AArch64RubbishCodePass::obfuscateControlFlow(MachineFunction &MF) {
  std::vector<MachineBasicBlock *> WorkList;
  std::vector<MachineBasicBlock *> AvailableBlocks;
  std::vector<MachineInstr *> Nops, FixPoint;
  std::vector<MachineBasicBlock *> RMBNewBlocks;
  randomMoveBasicBlock(MF, FixPoint, RMBNewBlocks);
  // S1: the fragments randomMoveBasicBlock cut out are chunks as well.
  if (SplitSymbols || ComputedBranches) {
    for (MachineBasicBlock *NB : RMBNewBlocks) {
      if (NB != &MF.front())
        ChunkBlocks.push_back(NB);
    }
  }
  for (MachineBasicBlock &MBB : MF) {
    insertNopInstruction(MBB, 1, Nops);
    bool isNew = false;
    for (auto *NB : RMBNewBlocks)
      if (NB == &MBB) { isNew = true; break; }
    if (!isNew)
      WorkList.push_back(&MBB);
  }
  unsigned Times = 1, BlockSize = 4;
  if (getenv("ARMRC_NO_SPLIT"))
    Times = 0;
  std::vector<MachineInstr *> Instrs;
  std::vector<ObfuscateInstrInfo> OIs;
  while (Times-- > 0) {
    std::vector<MachineBasicBlock *> IterList(WorkList);
    WorkList.clear();
    for (MachineBasicBlock *MBB : IterList) {
      Instrs.clear(), OIs.clear();
      generateObfuscateInfo(*MBB, OIs);
      MachineBasicBlock::iterator Ptr = MBB->begin(),
                                  FrameSetupInstr = MBB->begin(),
                                  FrameDestroyInstr = MBB->end();
      while (Ptr != MBB->end()) {
        if ((*Ptr).getFlag(MachineInstr::FrameSetup)) {
          Ptr++;
          FrameSetupInstr = Ptr;
        } else if ((*Ptr).getFlag(MachineInstr::FrameDestroy)) {
          Ptr--;
          FrameDestroyInstr = Ptr;
          break;
        } else {
          Ptr++;
        }
      }
      Ptr = FrameSetupInstr;
      while (Ptr != FrameDestroyInstr && Ptr != MBB->end()) {
        Instrs.push_back(&*Ptr);
        Ptr++;
      }

      if (Instrs.size() < 4) {
        continue;
      }
      unsigned State = 0, Reset = 1, ShouldSplit = 0;
      std::vector<MachineInstr *>::iterator Iter = Instrs.begin(),
                                            Bound = --Instrs.end(), Last;
      Iter++, Bound--;
      Last = Iter;
      std::vector<std::pair<MachineInstr *, MachineInstr *>> SplitPoints;
      while (Iter++ != Bound) {
        std::vector<MachineInstr *>::iterator TempIter = Iter;
        ++TempIter;
        if (TempIter == Instrs.end())
          break;
        ObfuscateInstrInfo *OI = nullptr;
        for (auto &Info : OIs) {
          if (Info.RawInst == *TempIter) {
            OI = &Info;
            break;
          }
        }
        if (!OI || (*Iter)->modifiesRegister(AArch64::SP, TRI) ||
            !OI->NZCVAvailable) {
          Reset = 1;
        } else {
          if (Reset) {
            Last = Iter;
            State = 0;
          }
          Reset = 0;
          if (State == BlockSize - 1) {
            ShouldSplit ^= 1;
            if (ShouldSplit) {
              SplitPoints.push_back(std::make_pair(*Last, *Iter));
            }
            Last = Iter;
          }
          State = (State + 1) % BlockSize;
        }
      }

      errs() << "[ARMRC] SP=" << SplitPoints.size() << " mbb=" << MBB->getNumber() << "\n";
      errs() << "[ARMRC] SP=" << SplitPoints.size() << " MBB=" << MBB->getNumber() << "\n";
      bool DidSplit = false;
      for (auto P = SplitPoints.begin(); P != SplitPoints.end(); P++) {
        if (MergedMBBs.count(P->first->getParent()->getNumber())) {
          continue;   // 合并回的块不再 split (悬空 successor 风险)
        }
        // 一次迭代只做一个 split: 多重 split 的 Header/Tail 指针在前次 split
        // 搬移后失效 (退化 MBB → transferSuccessors 崩溃), 逐次迭代更安全.
        if (DidSplit) {
          break;
        }
        MachineBasicBlock *NewBlock = splitBasicBlock(
            P->first->getParent(), P->first, P->second, FixPoint);

        if (NewBlock) {
          DidSplit = true;
          MachineBasicBlock::iterator Ptr = NewBlock->begin(),
                                      InsertEnd = NewBlock->end();
          Ptr++, InsertEnd--;
          while (Ptr++ != InsertEnd) {
            for (unsigned i = 0; i < 2; i++) {
              MachineInstr *Nop =
                  BuildMI(*NewBlock, *Ptr, Ptr->getDebugLoc(),
                          TII->get(AArch64::HINT))
                      .addImm(0)
                      .getInstr();
              Nops.push_back(Nop);
            }
          }
          // The executed edges are already BR X16. A second splitAt on a
          // random block faults in transferSuccessorsAndUpdatePHIs.
          WorkList.push_back(NewBlock);
          (void)AvailableBlocks;
        }
      }
    }
  }
  for (MachineInstr *Nop : Nops) {
    Nop->eraseFromParent();
  }
}

// Deterministic per-build chunk name: build seed + module + function + chunk
// index + a process-local salt.  Same source still yields different names per
// build/TU/function, and no substring of the original name survives.
// splitmix64 finaliser: a plain xor-shift mix collapses here (two adjacent
// chunk indices cancelled out and every chunk got the same label).
static uint64_t mixNameHash(uint64_t H, uint64_t V) {
  uint64_t X = H + V * 0x9e3779b97f4a7c15ULL;
  X ^= X >> 30;
  X *= 0xbf58476d1ce4e5b9ULL;
  X ^= X >> 27;
  X *= 0x94d049bb133111ebULL;
  X ^= X >> 31;
  return X;
}

// -obf-seed when the build sets one, otherwise a per-process clock seed (same
// recipe as ObfuscationSeed, but this does not consume the RNG stream, so the
// junk-code layout is unchanged whether or not -split-symbols is on).
static uint64_t splitNameSeed() {
  static uint64_t Seed = [] {
    uint64_t S = getObfSeed();
    if (!S)
      S = (uint64_t)std::time(nullptr) ^ ((uint64_t)std::clock() << 17) ^
          0x5A5A5A5AULL;
    return S;
  }();
  return Seed;
}

static std::string makeChunkSymbolName(StringRef Module, StringRef Fn,
                                       unsigned Idx) {
  static uint64_t Salt = 0;
  uint64_t H = mixNameHash(splitNameSeed(), (uint64_t)(size_t)hash_value(Module));
  H = mixNameHash(H, (uint64_t)(size_t)hash_value(Fn));
  H = mixNameHash(H, Idx);
  H = mixNameHash(H, ++Salt);
  char Buf[32];
  snprintf(Buf, sizeof(Buf), "_k%012llx",
           (unsigned long long)((H >> 16) & 0xffffffffffffULL));
  return std::string(Buf);
}

// Emit `NAME:` (plus `.globl`, optionally `.no_dead_strip`) at the first
// instruction of MBB, in the same linkage class as a real function symbol.
//
// `.globl` is what closes the oracle: `ld -x` deletes non-external symbols
// only, so a *local* chunk label survived while the real symbol did not, and
// "this start has a name" became a zero-false-positive real-function detector
// (SPLIT-SYMBOLS-S3.md 3: labelled_forged = 0).  `.private_extern` was measured
// first and is unusable: MC accepts the directive (MCSA_PrivateExtern), but
// ld64 rewrites N_PEXT definitions to non-external in the output ("non-external
// (was a private external)"), which puts the chunks straight back in the local
// class.  No MCSymbol surgery is involved either way: the directive goes
// through the same AsmParser path as the `.byte` filler this pass already uses.
static bool emitLinkageParityLabel(MachineBasicBlock *MBB,
                                   const std::string &Sym, bool NoDeadStrip,
                                   const AArch64InstrInfo *TII) {
  if (!MBB || MBB->empty())
    return false;
  std::string Text = ".globl " + Sym + "\n";
  if (NoDeadStrip)
    Text += ".no_dead_strip " + Sym + "\n";
  Text += Sym + ":\n";
  char *Persist = new char[Text.size() + 1];
  memcpy(Persist, Text.c_str(), Text.size() + 1);
  BuildMI(*MBB, MBB->begin(), nullptr, TII->get(AArch64::INLINEASM))
      .addExternalSymbol(Persist)
      .addImm(InlineAsm::Extra_HasSideEffects);
  return true;
}

static void appendSplitSidecar(const std::string &Records) {
  if (SplitSymbolsSidecar.empty() || Records.empty())
    return;
  static bool HeaderWritten = false;
  std::ofstream Ofs(SplitSymbolsSidecar, std::ios::app);
  if (!Ofs.is_open()) {
    errs() << "[split-symbols] cannot open " << SplitSymbolsSidecar << "\n";
    return;
  }
  if (!HeaderWritten) {
    HeaderWritten = true;
    Ofs << "polaris-split-symbols\t1\nseed\t" << std::hex << splitNameSeed()
        << std::dec << "\n";
  }
  Ofs << Records;
}

// Per-function record for the measurement, appended like the S1 sidecar.
static void appendComputedBranchSidecar(const std::string &Fn, unsigned Conv,
                                        unsigned Skip, unsigned Refused,
                                        unsigned Entries,
                                        const std::string &Table,
                                        const std::string &Records) {
  if (ComputedBranchesSidecar.empty())
    return;
  static bool HeaderWritten = false;
  std::ofstream Ofs(ComputedBranchesSidecar, std::ios::app);
  if (!Ofs.is_open()) {
    errs() << "[computed-branches] cannot open " << ComputedBranchesSidecar
           << "\n";
    return;
  }
  if (!HeaderWritten) {
    HeaderWritten = true;
    Ofs << "polaris-computed-branches\t1\nseed\t" << std::hex
        << splitNameSeed() << std::dec << "\nkey\t" << cbTableKey() << "\n";
  }
  Ofs << "fn\t" << Fn << "\tconv\t" << Conv << "\tskipped\t" << Skip
      << "\trefused\t" << Refused << "\tentries\t" << Entries << "\ttable\t"
      << Table << "\n";
  Ofs << Records;
}

// A seeded label at the function's own entry, so a start stays named no matter
// what happened to the function's real symbol.  Without it a *local-linkage*
// function is the only kind of start that loses its name to `ld -x` (measured
// on wbaes: 4 of 19 real starts), which is the mirror image of the oracle this
// change removes -- "unnamed" would select exactly the static functions.
std::string AArch64RubbishCodePass::emitEntrySymbol(MachineFunction &MF) {
  if (!SplitSymbols)
    return "";
  if (!MF.getTarget().getTargetTriple().isOSBinFormatMachO())
    return "";
  MachineBasicBlock &EntryMBB = MF.front();
  std::string Sym = makeChunkSymbolName(
      MF.getFunction().getParent()->getModuleIdentifier(),
      MF.getFunction().getName().str() + "$entry", 0);
  // No .no_dead_strip here: the alias sits in the function's own atom, so
  // -dead_strip keeps it exactly when it keeps the function.  Pinning it would
  // pin every function in the binary.
  if (!emitLinkageParityLabel(&EntryMBB, Sym, /*NoDeadStrip=*/false, TII))
    return "";
  return "entry\t" + MF.getFunction().getName().str() + "\t" + Sym + "\n";
}

// Give every split chunk its own label.  The label is emitted as inline asm at
// the block's first instruction, so it reaches MC and becomes a real nlist
// entry; ld64 derives LC_FUNCTION_STARTS from it as well.
void AArch64RubbishCodePass::emitChunkSymbols(MachineFunction &MF) {
  if (!SplitSymbols || ChunkBlocks.empty())
    return;
  if (!MF.getTarget().getTargetTriple().isOSBinFormatMachO()) {
    static bool Warned = false;
    if (!Warned) {
      Warned = true;
      errs() << "[split-symbols] only implemented for Mach-O, skipped\n";
    }
    return;
  }
  const Function &F = MF.getFunction();
  std::string FnName = F.getName().str();
  std::string ModName = F.getParent()->getModuleIdentifier();
  std::set<MachineBasicBlock *> Seen;
  std::string Records;
  unsigned Idx = 0;
  Records += emitEntrySymbol(MF);
  for (MachineBasicBlock *MBB : ChunkBlocks) {
    if (!MBB || MBB->empty() || !Seen.insert(MBB).second)
      continue;
    std::string Sym = makeChunkSymbolName(ModName, FnName, Idx);
    // A bare label starts a new atom and `ld -dead_strip` then drops the
    // unreferenced chunk (measured: the linked binary segfaults).  Keeping
    // .no_dead_strip lets the label stay in the nlist without turning the
    // chunk into a dead-strippable atom.
    if (!emitLinkageParityLabel(MBB, Sym, /*NoDeadStrip=*/true, TII))
      continue;
    Records += "chunk\t" + FnName + "\t" + std::to_string(Idx) + "\t" + Sym +
               "\t" + std::to_string(MBB->getNumber()) + "\n";
    ++Idx;
  }
  if (Idx == 0)
    return;
  if (getenv("ARMRC_DEBUG"))
    errs() << "[split-symbols] " << FnName << " chunks=" << Idx << "\n";
  Records = "fn\t" + FnName + "\t" + std::to_string(Idx) + "\n" + Records;
  appendSplitSidecar(Records);
}

void AArch64RubbishCodePass::process(MachineFunction &MF, ObfuscateOption &OO) {
  // S2: the table label has to exist before the split emits its own edges
  // (emitIndirectBranch adds entries while obfuscateControlFlow runs).
  if (ComputedBranches)
    CbTableLabel = makeCbTableLabel(
        MF.getFunction().getParent()->getModuleIdentifier(),
        MF.getFunction().getName().str());
  obfuscateControlFlow(MF);
  if (ComputedBranches)
    convertComputedBranches(MF);
  if (!getenv("ARMRC_NO_DATAFLOW"))
    obfuscateDataFlow(MF);
  if (ComputedBranches)
    emitComputedBranchTable(MF);
  // Labels go in last, so they sit at the chunk's true first instruction.
  emitChunkSymbols(MF);
  for (MachineBasicBlock &MBB : MF) {
    MBB.setMachineBlockAddressTaken();
    MBB.setLabelMustBeEmitted();
  }
  if (ComputedBranches) {
    appendComputedBranchSidecar(MF.getFunction().getName().str(), CbConverted,
                                CbSkipped, CbRefused, CbTargets.size(),
                                CbTableLabel, CbRecords);
    if (getenv("ARMRC_DEBUG"))
      errs() << "[computed-branches] " << MF.getFunction().getName()
             << " conv=" << CbConverted << " skipped=" << CbSkipped
             << " refused=" << CbRefused << "\n";
  }
}

bool AArch64RubbishCodePass::checkShouldProcess(MachineFunction &MF,
                                            ObfuscateOption &OO) {
  std::vector<MachineInstr *> Marks;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      if (MI.getOpcode() == AArch64::INLINEASM) {
        MachineOperand &MO = MI.getOperand(0);
        if (!MO.isSymbol()) {
          continue;
        }
        const char *Name = MO.getSymbolName();
        if (!strcmp(Name, "backend-obfu")) {
          Marks.push_back(&MI);
          OO.InsertRubbishCode = true;
        }
      }
    }
  }
  unsigned Num = Marks.size();
  for (MachineInstr *MI : Marks) {
    MI->eraseFromParent();
  }
  return Num != 0;
}

bool AArch64RubbishCodePass::runOnMachineFunction(MachineFunction &MF) {
  // Block numbers restart at 0 for every function. A merged block in one
  // function must not suppress splits in a later function.
  MergedMBBs.clear();
  ChunkBlocks.clear();
  CbTargets.clear();
  ChunkId.clear();
  CbTableLabel.clear();
  CbRecords.clear();
  CbConverted = CbSkipped = CbRefused = 0;
  MRI = &MF.getRegInfo();
  TII = MF.getSubtarget<AArch64Subtarget>().getInstrInfo();
  TRI = MF.getSubtarget().getRegisterInfo();

  ObfuscateOption OO;
  Anchors.clear();
  if (checkShouldProcess(MF, OO)) {
    process(MF, OO);
    return true;
  }
  // Functions the obfuscator does not touch still get the entry alias when
  // split-symbols is on: otherwise their start is named only by their real
  // symbol, so `ld -x` un-names exactly the static functions (wbaes: 4 of 19
  // real starts) and "unnamed" turns into a function detector of its own.
  if (SplitSymbols && !MF.getFunction().isDeclaration()) {
    std::string Rec = emitEntrySymbol(MF);
    if (!Rec.empty()) {
      appendSplitSidecar(Rec);
      return true;
    }
  }
  return false;
}
