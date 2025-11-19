// Frida script for hooking functions by predefined addresses
// Logs RCX, RDX, R8, R9 registers and return values


// Alternative format - just addresses (will use address as name)
const SIMPLE_ADDRESSES = [
    0x14044D2D4,
    0x140001000,
    0x140001060,
    0x140434DA0,
    0x1400010F0,
    0x14000D8E0,
    0x140432E50,
    0x1402CF0F0,
    0x14042D3B0,
    0x140011920,
    0x1402CF1B0,
    0x140017470,
    0x1400017C0,
    0x140437DA0,
    0x14001F190,
    0x1402C7E80,
    0x140420AB0,
    0x14001F120,
    0x1402C9D40,
    0x140424B60,
    0x1404352B0,
    0x14001F260,
    0x1402C4100,
    0x1404189A0,
    0x14001F1F0,
    0x1402C5FC0,
    0x14041CA50,
    0x14042F5F0,
    0x1402CF0A0,
    0x1402CF020,
    0x140432CC0,
    0x1402CF180,
    0x14001F2C0,
    0x1402CF340,
    0x1400250A0,
    0x1402C2240,
    0x1404148C0,
    0x140025240,
    0x1402BA740,
    0x140404400,
    0x1400251D0,
    0x1402BC600,
    0x140408560,
    0x1400252B0,
    0x14002B0B0,
    0x1402B8880,
    0x140400320,
    0x140001840,
    0x14002E020,
    0x1402B1060,
    0x1403F3990,
    0x14002B170,
    0x1402B4B00,
    0x1403F8190,
    0x1402AF1A0,
    0x1403EF8B0,
    0x1402AD2E0,
    0x1403EB7D0,
    0x140081590,
    0x1400D3850,
    0x140299E30,
    0x1403C31A0,
    0x140037060,
    0x1402CF220,
    0x14042F520,
    0x1404354A0,
    0x1402B4A90,
    0x140058A00,
    0x1400D38C0,
    0x140297F70,
    0x1403BF130,
    0x1400D3930,
    0x1402960B0,
    0x1403BAF80,
    0x140431970,
    0x1400D3A20,
    0x1402941F0,
    0x1403B6E40,
    0x14005E990,
    0x14029BD50,
    0x140001630,
    0x1402CDEF0,
    0x14042CCA0,
    0x1402CEEC0,
    0x14029BCF0,
    0x1402CE0F0,
    0x1400D3A90,
    0x140292330,
    0x1403B2D00,
    0x1402CE7B0,
    0x14042DE70,
    0x140432860,
    0x140001BB0,
    0x140438120,
    0x140004B50,
    0x140036CB0,
    0x14000D5D0,
    0x140005FC0,
    0x140006030,
    0x140001700,
    0x1402CE910,
    0x1400D3B00,
    0x140290470,
    0x1403AEBF0,
    0x14000D790,
    0x14042CD50,
    0x14000CB90,
    0x140005A10,
    0x140433580,
    0x14042E4F0,
    0x14042E590,
    0x1404324B0,
    0x140007BC0,
    0x140005900,
    0x140007260,
    0x140006B30,
    0x140006820,
    0x140002E70,
    0x14042E900,
    0x140443A00,
    0x140002FC0,
    0x14043D8D0,
    0x14000C970,
    0x14043D790,
    0x14043D760,
    0x140007DC0,
    0x140007590,
    0x140433800,
    0x14043A730,
    0x1402CE860,
    0x140433960,
    0x14043A940,
    0x1404338B0,
    0x14043A810,
    0x14000C140,
    0x140009600,
    0x140438050,
    0x14042EE20,
    0x140005010,
    0x140002070,
    0x140002110,
    0x14042F680,
    0x1400024E0,
    0x1402CEC80,
    0x140002810,
    0x1400028E0,
    0x1402CE280,
    0x14043D9D0,
    0x140003980,
    0x140005890,
    0x140005510,
    0x140002DE0,
    0x140002CD0,
    0x140430930,
    0x14042CE40,
    0x140446D30,
    0x140446C10,
    0x14000C8B0,
    0x140006B60,
    0x140002AB0,
    0x140005330,
    0x140002C00,
    0x1402CE3F0,
    0x14042E260,
    0x140435110,
    0x14044C0F4,
    0x14043F650,
    0x14043A510,
    0x14043FC50,
    0x14043F920,
    0x1404448F0,
    0x140447A90,
    0x140447EF0,
    0x140447C90,
    0x140447900,
    0x140449C20,
    0x14044A150,
    0x140447770,
    0x14044A840,
    0x140449E10,
    0x14044B090,
    0x14043FB90,
    0x14043E600,
    0x140437B50,
    0x140440F60,
    0x14043D1C0,
    0x140449D10,
    0x14044B820,
    0x14044B5D0,
    0x14044A8E0,
    0x140444F60,
    0x140001AD0,
    0x14042CDC0,
    0x14042D350,
    0x140438390,
    0x140435F50,
    0x140440DF0,
    0x14043FE70,
    0x14043E4B0,
    0x140444FF0,
    0x140448070,
    0x140446900,
    0x140443BE0,
    0x140443F90,
    0x1404467C0,
    0x140446670,
    0x1404487E0,
    0x1404485D0,
    0x140448300,
    0x14044AC20,
    0x140435EC0,
    0x14042D260,
    0x140446470,
    0x140001670,
    0x1402CDAD0,
    0x14042EFD0,
    0x140004090,
    0x140432A00,
    0x14043D630,
    0x1404393F0,
    0x140437ED0,
    0x140430B80,
    0x1400037D0,
    0x140446A90,
    0x140003650,
    0x140446A10,
    0x14043D600,
    0x140005D20,
    0x14042CFA0,
    0x1402CE2F0,
    0x1402CE990,
    0x140433D90,
    0x140433E50,
    0x140433D10,
    0x14043D7E0,
    0x140001E50,
    0x1404319D0,
    0x1403F7F10,
    0x140439A70,
    0x1402CE730,
    0x140435FF0,
    0x1404378C0,
    0x14043A050,
    0x1404364D0,
    0x140434850,
    0x14043BE60,
    0x1404415A0,
    0x140432260,
    0x14042DA00,
    0x1404462E0,
    0x140436CE0,
    0x140437940,
    0x140443770,
    0x140434E30,
    0x140437700,
    0x140432B50,
    0x1404416C0,
    0x1404440D0,
    0x14043EC60,
    0x140449720,
    0x140434560,
    0x1400D3B60,
    0x14028E5B0,
    0x1403AAB40,
    0x1402B3ED0,
    0x14043A3F0,
    0x140435090,
    0x1400D3BC0,
    0x14028C6F0,
    0x1403A6A90,
    0x1402B4000,
    0x140439CF0,
    0x140431B20,
    0x140066A60,
    0x140066BA0,
    0x1402CEEA0,
    0x140431900,
    0x1402CEE00,
    0x1402B4A30,
    0x1404358B0,
    0x140435C60,
    0x14043BCA0,
    0x14002D4C0,
    0x14002D340,
    0x140439710,
    0x14002D720,
    0x14002D760,
];


var advapi_module = Process.getModuleByName("advapi32.dll");
var kernel_module = Process.getModuleByName("kernel32.dll");
var ucrtbase = Process.getModuleByName("ucrtbase.dll");

// e4b8058f06f7061e8f0f 8ed15d23865ba2 42 7b23a695d9b27bc308a26d
// e4b8058f06f7061e8f0f8ed15d23865ba2428223a695d9b27bc308a26d
var gmtime = ucrtbase.getExportByName("_gmtime64_s");
var advapi = advapi_module.getExportByName("GetUserNameA");
var kernel = kernel_module.getExportByName("GetComputerNameA");
console.log("advapi32.dll!GetUserNameA: " + advapi);
console.log("kernel32.dll!GetComputerNameA: " + kernel);
console.log("ucrtbase.dll!_gmtime64: " + gmtime);

Interceptor.attach(advapi, {
    onEnter: function (args) {
        this.buf = args[0];
    },
    onLeave: function (retval) {
        this.buf.writeUtf8String("TheBoss");
    }
});

Interceptor.attach(kernel, {
    onEnter: function (args) {
        this.buf = args[0];
    },
    onLeave: function (retval) {
        this.buf.writeUtf8String("THUNDERNODE");

    }
});

Interceptor.attach(gmtime, {
    onEnter: function (args) {
        console.log("gmtime64 called");
        this.time = args[0]
    },
    onLeave: function (retval) {
        // int    tm_sec   seconds [0,61]
        // int    tm_min   minutes [0,59]
        // int    tm_hour  hour [0,23]
        // int    tm_mday  day of month [1,31]
        // int    tm_mon   month of year [0,11]
        // int    tm_year  years since 1900
        // int    tm_wday  day of week [0,6] (Sunday = 0)
        // int    tm_yday  day of year [0,365]
        // int    tm_isdst daylight savings flag
        // write time for 2025-08-20 06:00:00

        this.time.writeByteArray([
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x06,0x00,0x00,0x00,
            0x14,0x00,0x00,0x00,
            0x07,0x00,0x00,0x00,
            0x7d,0x00,0x00,0x00,
            0x03,0x00,0x00,0x00,
            0xe7,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00])
    }
}); 
// C4N7_ST4R7_A_FLAR3_WITHOUT_4_$PARK@FLARE-ON.COM



// Helper function to check if a pointer points to a printable string
function tryReadString(ptr, maxLength = 50000) {
    if (!ptr || ptr.isNull()) {
        return null;
    }
    
    try {
        // Try to read as ASCII string first
        let str = ptr.readAnsiString(maxLength);
        if (str && isPrintableString(str)) {
            return { type: 'ASCII', value: str.length > maxLength ? str.substring(0, maxLength) + '...' : str };
        }
    } catch (e) {}
    
    try {
        // Try to read as UTF-16 (Unicode) string
        let str = ptr.readUtf16String(maxLength);
        if (str && isPrintableString(str)) {
            return { type: 'UTF-16', value: str.length > maxLength ? str.substring(0, maxLength) + '...' : str };
        }
    } catch (e) {}
    
    try {
        // Try to read as UTF-8 string
        let str = ptr.readUtf8String(maxLength);
        if (str && isPrintableString(str)) {
            return { type: 'UTF-8', value: str.length > maxLength ? str.substring(0, maxLength) + '...' : str };
        }
    } catch (e) {}
    
    return null;
}

// Helper function to check if a string contains mostly printable characters
function isPrintableString(str) {
    if (!str || str.length < 2) return false;
    
    let printableCount = 0;
    let totalCount = str.length;
    
    for (let i = 0; i < str.length; i++) {
        let charCode = str.charCodeAt(i);
        // Consider printable: space (32) to tilde (126), plus some common extended chars
        if ((charCode >= 32 && charCode <= 126) || 
            charCode === 9 || charCode === 10 || charCode === 13 || // tab, newline, carriage return
            (charCode >= 160 && charCode <= 255)) { // extended ASCII
            printableCount++;
        }
    }
    
    // String is considered printable if at least 80% of characters are printable
    return (printableCount / totalCount) >= 0.8;
}

// Helper function to format register/argument output with potential string value
function formatValueWithString(value, label) {
    let output = `  ${label}: 0x${value.toString(16).padStart(16, '0')}`;
    
    let stringInfo = tryReadString(value);
    if (stringInfo) {
        output += ` ("${stringInfo.value}" [${stringInfo.type}])`;
    }
    
    return output;
}

function hookFunctionByAddress(addressStr, functionName = null) {
    try {
        const funcAddress = ptr(addressStr);
        const displayName = functionName || `func_${addressStr}`;
        
        console.log(`[+] Setting hook at ${funcAddress} (${displayName})`);
        
        Interceptor.attach(funcAddress, {
            onEnter: function(args) {
                // Store context for onLeave
                this.functionName = displayName;
                this.functionAddress = addressStr;
                this.timestamp = Date.now();
                
                // Read x64 registers at function entry
                const rcx = this.context.rcx;
                const rdx = this.context.rdx;
                const r8 = this.context.r8;
                const r9 = this.context.r9;
                
                console.log(`\n[CALL] ${displayName} @ ${addressStr} - ${new Date().toISOString()}`);
                
                // Log registers with string detection
                // console.log(formatValueWithString(rcx, "RCX"));
                // console.log(formatValueWithString(rdx, "RDX"));
                // console.log(formatValueWithString(r8, "R8 "));
                // console.log(formatValueWithString(r9, "R9 "));
                
                // Log first few arguments with string detection
                console.log(formatValueWithString(args[0] || ptr(0), "Args[0]"));
                console.log(formatValueWithString(args[1] || ptr(0), "Args[1]"));
                console.log(formatValueWithString(args[2] || ptr(0), "Args[2]"));
                console.log(formatValueWithString(args[3] || ptr(0), "Args[3]"));
            },
            
            onLeave: function(retval) {
                const duration = Date.now() - this.timestamp;
                
                console.log(`[RETURN] ${this.functionName} @ ${this.functionAddress}`);
                console.log(`  Return Value: 0x${retval.toString(16).padStart(16, '0')} (${retval})`);
                console.log(`  Duration: ${duration}ms`);
                console.log(`  ${'='.repeat(70)}`);
            }
        });
        
        return true;
        
    } catch (error) {
        console.log(`[-] Error hooking address ${addressStr}: ${error.message}`);
        return false;
    }
}

// Function to validate if address is accessible
function validateAddress(addressStr) {
    try {
        const addr = ptr(addressStr);
        // Try to read a byte to check if address is valid
        addr.readU8();
        return true;
    } catch (error) {
        console.log(`[-] Invalid/inaccessible address: ${addressStr} - ${error.message}`);
        return false;
    }
}

// Function to display current process information
function showProcessInfo() {
    console.log(`[INFO] Process ID: ${Process.id}`);
    console.log(`[INFO] Process Name: ${Process.getCurrentThreadId()}`);
    console.log(`[INFO] Architecture: ${Process.arch}`);
    
    // Show main module info
    const mainModule = Process.enumerateModules()[0];
    console.log(`[INFO] Main Module: ${mainModule.name}`);
    console.log(`[INFO] Base Address: ${mainModule.base}`);
    console.log(`[INFO] Module Size: 0x${mainModule.size.toString(16)}`);
    console.log("");
}

// Main execution
console.log("[+] Starting address-based function hooking script...");
showProcessInfo();

let successCount = 0;
let totalCount = 0;

// Hook functions from simple address list
if (SIMPLE_ADDRESSES.length > 0) {
    console.log(`[+] Hooking ${SIMPLE_ADDRESSES.length} functions from address list...`);
    
    SIMPLE_ADDRESSES.forEach(function(address) {
        totalCount++;
        
        // Validate address before hooking
        if (validateAddress(address)) {
            if (hookFunctionByAddress(address)) {
                successCount++;
            }
        }
    });
} else {
    console.log("[-] No addresses defined in SIMPLE_ADDRESSES array");
}

console.log(`\n[+] Hook setup complete: ${successCount}/${totalCount} functions hooked successfully`);

if (successCount > 0) {
    console.log("[+] Script ready - waiting for function calls...\n");
} else {
    console.log("[-] No functions were successfully hooked. Check your addresses.\n");
}

// Optional: Enable this to get stack traces
/*
// Add stack trace to onEnter if needed
onEnter: function(args) {
    // ... existing code ...
    
    console.log("  Stack Trace:");
    Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 5)  // Show top 5 frames
        .forEach(function(frame, i) {
            console.log(`    ${i}: ${frame}`);
        });
}
*/