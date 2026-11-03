#include "AArch64.h"
#include "AArch64InstrInfo.h"
#include "AArch64Subtarget.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>
#include <set>
#include <vector>
using namespace llvm;

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
  void obfuscateControlFlow(MachineFunction &MF);
  bool containsCall(MachineBasicBlock *MBB);

private:
  MachineRegisterInfo *MRI = nullptr;
  const AArch64InstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
  MachineFrameInfo *MFI = nullptr;
  // Instructions around which no garbage may be inserted (BL and the
  // branch that the RET lands on); inserting between them breaks the
  // call-shaped split return path.
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
  return Available[rand() % Available.size()];
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
    uint64_t Imm = rand() % 4096;
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
    uint64_t Shift = rand() % (Is64Bit ? 64 : 32);
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

// Split MBB between Header and Tail and move the body to the end of the
// function, turning the straight-line flow into MBB -> (garbage fallthrough)
// ... Body (at function end) -> End.
// The "call" trick on ARM64: BL Body makes LR point after the BL, and Body
// ends with RET which jumps back to LR. Bodies containing calls are rejected
// because a nested BL would clobber LR.
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

  if (containsCall(Body) || containsCall(End)) {
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

  // AArch64 SP must stay 16-byte aligned at all times (hardware trap
  // EXC_ARM_SP_ALIGN otherwise). Round the reservation up.
  uint64_t StackSize = (MFI->estimateStackSize(*MF) + 15) & ~15ULL;

  // Call-shaped split. Split points are confined between FrameSetup and
  // FrameDestroy (see obfuscateControlFlow), so Body never restores LR --
  // RET in Body safely returns to the instruction after BL, which is the
  // branch back to End. This mirrors the X86 CALL/RET disguise and makes
  // Body look like a standalone function tail to decompilers.
  FixPoint.push_back(BuildMI(*MBB, MBB->end(), nullptr, TII->get(AArch64::B))
                         .addMBB(Body)
                         .getInstr());
  FixPoint.push_back(BuildMI(*MBB, MBB->end(), nullptr, TII->get(AArch64::B))
                         .addMBB(End)
                         .getInstr());

  MachineInstr *MI = &*End->begin();
  // RubbishSize must be a multiple of 4 (AArch64 instructions are 4-byte
  // aligned) and <= 4095 so it fits in an ADDXri imm12.
  unsigned RubbishSize = ((rand() % 30 + 20) * 4) & 0xFFC;
  if (getenv("ARMRC_NO_DIRTY"))
    RubbishSize = 0;

  BuildMI(*Body, Body->end(), nullptr, TII->get(AArch64::B))
      .addMBB(End)
      .getInstr();

  // Dirty bytes live in a dedicated block that no runtime path reaches.
  // Landing past them via LR skew is layout-fragile: any instruction
  // inserted at End->begin() (dataflow garbage, later splits) shifts the
  // target. The RET here always returns to the fixed branch after BL.
  MachineBasicBlock *DirtyBB = MF->CreateMachineBasicBlock();
  MF->insert(++MachineFunction::iterator(End), DirtyBB);
  DirtyBB->addSuccessor(End);
  std::vector<unsigned char> RandBytes;
  for (unsigned i = 0; i < RubbishSize; i++) {
    RandBytes.push_back(rand() & 0xff);
  }
  MachineInstr *BrTo = BuildMI(*DirtyBB, DirtyBB->end(), nullptr,
                               TII->get(AArch64::B))
                            .addMBB(End)
                            .getInstr();
  insertDirtyBytes(BrTo, RandBytes);
  DirtyBB->setMachineBlockAddressTaken();
  DirtyBB->setLabelMustBeEmitted();

  Body->moveBefore(&*MF->end());
  DirtyBB->moveBefore(&*MF->end());
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
    MachineBasicBlock *Before = MoveList[rand() % MoveList.size()];
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
    const RubbishDesc &D = Descs[rand() % Descs.size()];
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
          WorkList.push_back(NewBlock);

          AvailableBlocks.clear();
          for (MachineBasicBlock &MBB : MF) {
            if (&MBB == &MF.front() ||
                std::find(WorkList.begin(), WorkList.end(), &MBB) !=
                    WorkList.end() ||
                MBB.size() < 4) {
              continue;
            }
            AvailableBlocks.push_back(&MBB);
          }
          if (AvailableBlocks.size() != 0) {
            MachineBasicBlock *InsertInto =
                AvailableBlocks[rand() % AvailableBlocks.size()];
            unsigned InsertPos = InsertInto->size() / 2;

            for (MachineInstr &MI : *InsertInto) {
              InsertPos--;
              if (std::find(FixPoint.begin(), FixPoint.end(), &MI) !=
                  FixPoint.end()) {
                continue;
              }
              if (InsertPos <= 0) {
                if (MI.getFlag(MachineInstr::FrameSetup) ||
                    MI.getFlag(MachineInstr::FrameDestroy) ||
                    InsertInto->size() < 6) {
                  continue;
                }
                MachineBasicBlock *InsertBefore =
                    InsertInto->splitAt(MI, true, nullptr);
                BuildMI(*InsertInto, InsertInto->end(), nullptr,
                        TII->get(AArch64::B))
                    .addMBB(InsertBefore);
                NewBlock->moveBefore(InsertBefore);
                break;
              }
            }
          }
        }
      }
    }
  }
  for (MachineInstr *Nop : Nops) {
    Nop->eraseFromParent();
  }
}

void AArch64RubbishCodePass::process(MachineFunction &MF, ObfuscateOption &OO) {
  obfuscateControlFlow(MF);
  if (getenv("ARMRC_NO_DATAFLOW"))
    return;
  obfuscateDataFlow(MF);
  for (MachineBasicBlock &MBB : MF) {
    MBB.setMachineBlockAddressTaken();
    MBB.setLabelMustBeEmitted();
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
  if (const char *Seed = getenv("ARMRC_SEED"))
    srand(atoi(Seed));
  else
    srand(time(0));
  MRI = &MF.getRegInfo();
  TII = MF.getSubtarget<AArch64Subtarget>().getInstrInfo();
  TRI = MF.getSubtarget().getRegisterInfo();
  MFI = &MF.getFrameInfo();

  ObfuscateOption OO;
  Anchors.clear();
  if (checkShouldProcess(MF, OO)) {
    process(MF, OO);
    return true;
  }
  return false;
}
