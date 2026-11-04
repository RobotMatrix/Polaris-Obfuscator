

#include "llvm/Transforms/Obfuscation/Pipeline.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Obfuscation/AliasAccess.h"
#include "llvm/Transforms/Obfuscation/BogusControlFlow2.h"
#include "llvm/Transforms/Obfuscation/CustomCC.h"
#include "llvm/Transforms/Obfuscation/Flattening.h"
#include "llvm/Transforms/Obfuscation/GlobalsEncryption.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/IndirectCall.h"
#include "llvm/Transforms/Obfuscation/LinearMBA.h"
#include "llvm/Transforms/Obfuscation/MergeFunction.h"
#include "llvm/Transforms/Obfuscation/Substitution.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include <set>
using namespace llvm;
using namespace polaris;

static cl::list<std::string> Passes("passes", cl::CommaSeparated, cl::Hidden,
                                    cl::desc("Obfuscation passes"));
static cl::opt<std::string> PolicyFile("policy-file", cl::Hidden,
                                       cl::desc("JSON policy file for no-marking obfuscation"));

struct LowerSwitchWrapper : LowerSwitchPass {
  static bool isRequired() { return true; }
};

static void addObfuscationPass(ModulePassManager &MPM, StringRef Name) {
  if (Name == "ccc") {
    MPM.addPass(CustomCC());
  } else if (Name == "sub") {
    FunctionPassManager FPM;
    FPM.addPass(Substitution());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  } else if (Name == "mba") {
    FunctionPassManager FPM;
    FPM.addPass(LinearMBA());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  } else if (Name == "alias") {
    MPM.addPass(AliasAccess());
  } else if (Name == "bcf") {
    FunctionPassManager FPM;
    FPM.addPass(BogusControlFlow2());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  } else if (Name == "merge") {
    MPM.addPass(MergeFunction());
  } else if (Name == "fla") {
    MPM.addPass(Flattening());
  } else if (Name == "indbr") {
    FunctionPassManager FPM;
    FPM.addPass(IndirectBranch());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  } else if (Name == "indcall") {
    FunctionPassManager FPM;
    FPM.addPass(IndirectCall());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  } else if (Name == "gvenc") {
    MPM.addPass(GlobalsEncryption());
  } else {
    report_fatal_error(Twine("unknown obfuscation pass '") + Name + "'");
  }
}

ModulePassManager buildObfuscationPipeline() {
  ModulePassManager MPM;
  // JSON 策略文件: 无源码标记 → 从文件读 pass 列表 + 目标函数
  if (!PolicyFile.empty()) {
    polaris::loadPolicyFile(PolicyFile);
  }

  // Fixed order, independent of the order written on the command line.
  // sub/mba rewrite data first, then bogus CFG, then flattening, then
  // indirect control transfers. String decryption runs last so it sees the
  // final users of each global.
  static const char *Order[] = {"ccc",  "sub",     "mba",   "alias", "bcf",
                                "merge", "fla",     "indbr", "indcall",
                                "gvenc"};
  std::set<std::string> Wanted;
  for (const std::string &Pass : Passes) {
    bool Known = false;
    for (const char *Name : Order) {
      if (Pass == Name) {
        Known = true;
        break;
      }
    }
    if (!Known)
      report_fatal_error(Twine("unknown obfuscation pass '") + Pass + "'");
    Wanted.insert(Pass);
  }
  for (const char *Name : Order) {
    if (Wanted.count(Name))
      addObfuscationPass(MPM, Name);
  }
  return MPM;
}
