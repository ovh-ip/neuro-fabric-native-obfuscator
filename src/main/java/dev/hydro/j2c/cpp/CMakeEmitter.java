package dev.hydro.j2c.cpp;

import java.util.List;

/**
 * Emits a clean cross-platform CMake C++20 build project supporting Windows (x86_64/arm64/x86),
 * Linux (x86_64/aarch64), and macOS (x86_64/arm64/universal) with stripped hidden symbols
 * and single JNI_OnLoad export.
 */
public final class CMakeEmitter {

    public static String emitCMakeLists(String libBaseName, List<String> shardFileNames) {
        StringBuilder sources = new StringBuilder();
        sources.append("    hydro_memory.cpp\n");
        sources.append("    hydro_crypto.cpp\n");
        sources.append("    hydro_security.cpp\n");
        sources.append("    hydro_net.cpp\n");
        sources.append("    hydro_jni_bridge.cpp\n");
        sources.append("    hydro_vm_core.cpp\n");
        sources.append("    hydro_tables.cpp\n");
        for (String sf : shardFileNames) {
            sources.append("    ").append(sf).append("\n");
        }
        String safeTarget = libBaseName.replaceAll("[^A-Za-z0-9_]", "_");
        if (safeTarget.isEmpty() || Character.isDigit(safeTarget.charAt(0))) {
            safeTarget = "hydro_" + safeTarget;
        }

        return """
cmake_minimum_required(VERSION 3.16)
project(%s LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

set(HYDRO_JDK_HOME "" CACHE PATH "Optional path to JDK containing include/jni.h")

if(HYDRO_JDK_HOME)
    set(HYDRO_JNI_INCLUDES "${HYDRO_JDK_HOME}/include")
    if(WIN32)
        list(APPEND HYDRO_JNI_INCLUDES "${HYDRO_JDK_HOME}/include/win32")
    elseif(APPLE)
        list(APPEND HYDRO_JNI_INCLUDES "${HYDRO_JDK_HOME}/include/darwin")
    else()
        list(APPEND HYDRO_JNI_INCLUDES "${HYDRO_JDK_HOME}/include/linux")
    endif()
else()
    find_package(JNI REQUIRED)
    set(HYDRO_JNI_INCLUDES ${JNI_INCLUDE_DIRS})
endif()

add_library(%s SHARED
%s)

target_include_directories(%s PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    ${HYDRO_JNI_INCLUDES}
)

if(WIN32)
    set_target_properties(%s PROPERTIES PREFIX "" OUTPUT_NAME "%s")
else()
    set_target_properties(%s PROPERTIES OUTPUT_NAME "%s")
endif()

if(MSVC)
    target_compile_options(%s PRIVATE /O2 /GR- /EHs-c- /w)
    target_link_options(%s PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports.def")
else()
    target_compile_options(%s PRIVATE
        -O2 -fno-rtti -fno-exceptions -fvisibility=hidden
        -fno-ident -ffunction-sections -fdata-sections -w
    )
    if(WIN32)
        target_link_options(%s PRIVATE
            -static -static-libgcc -static-libstdc++
            -Wl,--exclude-all-symbols -Wl,--gc-sections -s
            "${CMAKE_CURRENT_SOURCE_DIR}/exports.def"
        )
    elseif(APPLE)
        target_link_options(%s PRIVATE
            -Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports.exp
            -Wl,-dead_strip -Wl,-x
        )
    else()
        target_link_libraries(%s PRIVATE ${CMAKE_DL_LIBS} pthread)
        target_link_options(%s PRIVATE
            -static-libgcc -static-libstdc++
            -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map
            -Wl,--gc-sections -Wl,-s
        )
    endif()
endif()
""".formatted(
                safeTarget,
                safeTarget,
                sources.toString(),
                safeTarget,
                safeTarget, libBaseName,
                safeTarget, libBaseName,
                safeTarget,
                safeTarget,
                safeTarget,
                safeTarget,
                safeTarget,
                safeTarget, safeTarget
        );
    }

    public static String emitLinuxVersionScript() {
        return "{\n    global: JNI_OnLoad;\n    local: *;\n};\n";
    }

    public static String emitMacOsExportsList() {
        return "_JNI_OnLoad\n";
    }

    public static String emitBuildInstructions(String libBaseName) {
        return """
HydroJ2C Cross-Platform C++20 CMake Build Project
==================================================
Targets supported: Windows (x86_64/arm64/x86), Linux (x86_64/aarch64), macOS (x86_64/arm64).

Examples:
  # Host OS (auto-detect JAVA_HOME / JNI):
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
  cmake --build build --parallel

  # Explicit JDK (e.g. Linux / macOS / cross-arch):
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DHYDRO_JDK_HOME="$JAVA_HOME"
  cmake --build build --parallel

  # macOS Universal Binary (Apple Silicon arm64 + Intel x86_64):
  cmake -S . -B build-mac -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"
  cmake --build build-mac --parallel

  # Linux ARM64 cross-compile from x86_64 Linux:
  cmake -S . -B build-arm64 -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++
  cmake --build build-arm64 --parallel

To pack multi-OS binaries back into a single universal JAR:
  Copy binaries into e.g. dist-natives/<os>-<arch>/ (%s.dll, lib%s.so, lib%s.dylib)
  and run HydroJ2C with `--natives-dir dist-natives`.
""".formatted(libBaseName, libBaseName, libBaseName);
    }
}
