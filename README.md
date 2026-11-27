# HydroJ2C — Нативный Java-to-C++ обфускатор, полиморфная VM и сервер динамических сессий

**HydroJ2C** — кроссплатформенный протектор Java-байткода (стандартные runnable/library JAR-файлы и моды Fabric/Mixin), компилирующий бизнес-логику в нативные библиотеки (`.dll` / `.so` / `.dylib`) на C++20 и защищающий нативный бинарник от статического и динамического реверс-инжиниринга.

---

## Ключевые возможности

### 1. Обфускация байткода и C++20 кодогенерация
- **Поддержка любых JAR-целей:**
  - Автоматическое определение и изоляция **Fabric-модов** (`fabric.mod.json` entrypoints, 1-строчный `@Mixin`-трамплин).
  - **Стандартные runnable JAR** (`java -jar`, `Main-Class`), **library JAR** на multi-JAR classpath, а также точечный режим `-a / --annotations` (`@Native`, `@NativeVM`, `@NotNative`).
- **Три уровня защиты (`--tier`):**
  - `FAST` — базовая трансляция критичных методов + шифрование констант.
  - `STRONG` — Control Flow Flattening (`CFF`), Mixed Boolean-Arithmetic (`MBA`), opaque predicates, обфускация строкового/классового пула и шифрование классов в `.fucked` + декойные `.class`/`.fucked`.
  - `ULTRA` — полиморфная **Native VM** со случайной перестановкой опкодов на каждую сборку и **разреженной 32-битной биективной диспетчеризацией** (`(op * dispMul) ^ dispXor`), ломающей восстановление jump-таблиц в декомпиляторах.
- **Кроссплатформенность (CMake + Multi-OS JAR):**
  - Генерация готового **CMake C++20 проекта** (`--cmake`, `--cmake-out <dir>`) под Windows / Linux / macOS (`x86_64`, `ARM64`, `x86`).
  - Автоматическая упаковка нативов (`--natives-dir <dir>`) внутрь `natives/<os>-<arch>/` (опционально с шифрованием `--encrypt-dll`) или работа с внешней библиотекой (`--external-dll`).

### 2. Модульный нативный рантайм C++20 (`src/main/resources/native/`)
- `hydro_runtime.hpp`, `hydro_crypto.hpp` — общие структуры, типы и примитивы.
- `hydro_memory.cpp` — аллокаторы, obfuscated pointer cookies (`g_ptr_cookie`), безопасное затирание памяти.
- `hydro_crypto.cpp` — **X25519**, **ChaCha20**, **HMAC-SHA256**, **HKDF-SHA256**, CSPRNG (`BCryptGenRandom` через динамический экспорт без статического импорта / `/dev/urandom`).
- `hydro_security.cpp` — анти-отладка и анти-тампер:
  - Обход PEB + хэш-резолвинг WinAPI (`FNV-1a`) с поддержкой PE export forwarders — минимальная таблица импортов без строк API в `.rdata`.
  - Детект отладчиков и инструментов анализа на старте и периодически в рантайме (`PEB`, `NtQueryInformationProcess`, аппаратные `Dr0..Dr3`, `TracerPid`, `sysctl`, поиск `frida-*`, `x64dbg.dll`, `scyllahide.dll`, `vehdebug-*`, `cheatengine-*`, `titanengine.dll`, `sharpod.dll`, `minhook.x64.dll`).
  - Скрытие рабочего heartbeat-потока от отладчика (`NtSetInformationThread` / `ThreadHideFromDebugger`).
  - Самопроверка всех секций кода `IMAGE_SCN_CNT_CODE` (`VirtualQuery`), детектор inline-хуков (`0xCC`/`0xE9`/`JMP`/`BRK`) и проверка печати таблицы символов `g_hydro_seal_box`.
- `hydro_net.cpp` — клиентский E2EE протокол v2 (без `<stdio.h>` и без открытых JSON/HTTP-ключей):
  - Полностью исключается из сборки при отключённом `--server-url`, а при включённом использует динамическую загрузку `winhttp.dll`/`advapi32.dll`, `CreateFileA` через PEB и шифрованный пул.
  - Инлайн-guard сессии (`inline_session_ok` + `HY_MBA_SESS_ALIVE_MAGIC`), watchdog прогресса heartbeat-потока, защита от заморозки таймеров и `destroy_session_keys()` со стиранием ключей при отзыве.
- `hydro_jni_bridge.cpp` — единый экспорт `JNI_OnLoad` (+ `JNI_OnUnload` logout при серверной привязке), динамическая регистрация методов через `RegisterNatives`, верификация JAR/ресурсов и загрузка `.fucked` через `DefineClass`.
- `hydro_vm_core.cpp` — стековая нативная ВМ с шифрованным байткодом, разреженным биективным диспетчером и инлайн-проверкой сессии.
- `JavaPreHardener` / `ConstructorOutliner` / `ClassRewriter` — вынос `<init>`/`<clinit>` в нативку, шифрование остаточных строковых и числовых констант в оставшихся `.class` (включая интерфейсы и `HLoader`), SplitMix64 для `--encrypt-dll` и зануление временных меток PE (`COFF TimeDateStamp`, `ExportDirectory`, `DebugDirectory`).

### 3. Spring Boot сервер лицензий и динамических сессий (`server/`)
Сервер (`Java 21`, `Spring Boot 3.5.0`, `Spring Data JPA`, `H2`) намертво привязывает нативный код к активной онлайн-сессии так, что без валидной лицензии клиент не может запустить даже отдельные методы:
- **Split-secret + CFF/VM Server State Coupling:** во время сборки `HydroJ2C` отделяет `serverVmShare`, `serverVaultShare` и массив `dynParams[8]` в манифест `<output>-server.json` (или сразу на сервер через `--server-admin-token`). В клиентский JAR/DLL эти секреты не попадают; ими защищены `.fucked`-классы, ключ Native VM и начальное состояние CFF-автомата в каждом скомпилированном методе.
- **Протокол E2EE v2 поверх всего трафика:** **все** запросы и ответы (`/handshake`, `/heartbeat`, `/logout`) передаются в зашифрованных ChaCha20 + HMAC-SHA256 конвертах поверх X25519 + HKDF-SHA256 без открытых полей `licenseKey`/`hwid`/`jarDigest`/`sessionId` в HTTP-запросах.
- **Full Key Ratcheting & Anti-Replay:** сервер ведёт кэш повторов handshake (`(k, n)`), привязывает сессию к HWID и `sessionGuard`, и на каждом heartbeat вращает **все** ключи (`encKey`, `macKey`, `rollingKey`, `guard`) через HMAC-epoch ratchet.
- **Мгновенный live-бан:** отзыв лицензии/билда админ-запросом, истечение lease или остановка heartbeat-потока немедленно уничтожают ключи в памяти активного клиента.

---

## Быстрый старт

### 1. Сборка и полный прогон тестов (Windows / PowerShell)
Требуются JDK 21+ (`javac`, `jar`, `javap`) и `g++` (MinGW-w64) или `clang++` в `PATH`:

```powershell
# Сборка протектора build\hydro-j2c.jar
powershell -ExecutionPolicy Bypass -File .\hydro.ps1 build

# Полный E2E прогон: Fabric-мод, Runnable JAR, Library JAR, CMake-сборка,
# Spring Boot сервер (X25519 + ChaCha20 + rolling heartbeat + live revoke) и аудит DLL
powershell -ExecutionPolicy Bypass -File .\hydro.ps1 test
```

### 2. Защита JAR без сервера
```powershell
# Максимальный уровень (STRONG) с автодетектом классов мода или приложения
java -jar build\hydro-j2c.jar -i app.jar -o app-protected.jar --tier STRONG

# Режим ULTRA (CFF+MBA + Native VM) + экспорт кроссплатформенного CMake-проекта
java -jar build\hydro-j2c.jar -i app.jar -o app-ultra.jar --tier ULTRA --cmake --cmake-out build\cmake-proj
```

### 3. Сборка с сервером лицензий (`server/`)
1. Соберите и запустите Spring Boot сервер:
```powershell
cd server
gradle bootRun
```
При первом запуске сервер создаст `./data/server-keys.json` и выведет `serverPubHex` (через `/api/v1/health`) и `adminToken`.

2. Защитите JAR с привязкой к серверу и авто-регистрацией билда:
```powershell
java -jar build\hydro-j2c.jar `
  -i app.jar -o app-srv.jar --tier ULTRA `
  --server-url http://127.0.0.1:8080 `
  --server-pubkey <64-hex-pubkey> `
  --product-id my-product `
  --server-admin-token <admin-token> `
  --server-heartbeat-sec 15
```

3. Выпустите лицензию и запустите защищённый JAR с ключом `-Dhydro.key=...` (либо через переменную окружения `HYDRO_LICENSE_KEY` / файл `hydro.key`):
```powershell
java -Dhydro.key=HY-YOUR-LICENSE-KEY -jar app-srv.jar
```

---

## Параметры CLI

```text
Usage:
  hydro -i <input.jar> [-o <output-protected.jar>] [-d <output.dll>] [options]

Options:
  -a, --annotations            Process only @Native classes/methods (and respect @NotNative / @NativeVM)
  -w, --white-list <file>      Read whitelist class/method patterns from file
  -b, --black-list <file>      Read blacklist class/method patterns from file
  --tier <FAST|STRONG|ULTRA>   Protection level (default: STRONG; ULTRA adds Native VM)
  --include <glob>             Class/package glob (auto-detects Fabric packages, or protects all classes in standard JARs)
  --exclude <glob>             Exclude class/package glob
  --vm <glob>                  Force matching classes/methods into randomized Native VM
  --vm-exclude <glob>          Keep matching classes/methods in fast CFF native C++ instead of VM
  --external-dll [path]        Load external .dll instead of embedding inside JAR natives/
  --encrypt-dll                Also encrypt the DLL payload inside natives/
  --junk <N>                   Generate N decoy .class & .fucked files in nested junk folders (default: 300)
  --no-junk                    Disable junk classes/folders
  --no-fucked                  Keep protected stub classes as .class instead of encrypted .fucked
  --no-mixins                  Disable automatic @Mixin hook outlining
  --no-ctor-outline            Disable <init> body outlining
  --no-anti-debug              Disable PEB/NtQuery/DrX anti-debug checks
  --no-anti-dump               Disable JNI vtable hook & anti-dump checks
  --no-anti-tamper             Disable DLL & JAR integrity verification
  --cmake                      Build host native library via generated CMake project
  --cmake-out <dir>            Export cross-platform CMake C++20 project (Win/Linux/macOS, x86/ARM)
  --natives-dir <dir>          Bundle prebuilt .dll/.so/.dylib libraries into JAR natives/<os>-<arch>/
  -j, --jobs <N>               Parallel C++ compile jobs
  --jdk <path>                 Path to JDK with jni.h
  --compiler <path>            Path to g++/clang++
  --seed <hex/int>             Deterministic build seed
  --server-url <url>           Bind runtime/vault/VM secrets to Spring licensing server
  --server-pubkey <64-hex>     Pinned X25519 server public key from Spring server startup
  --product-id <id>            Product identifier registered on server
  --build-id <id>              Override build identifier registered on server
  --server-key-file <path>     Local file holding license key (default: hydro.key)
  --license-key <key>          Optional baked license key for private builds
  --manifest-out <path>        Where to save <output>-server.json build secret bundle
  --server-admin-token <tok>   Auto-register protected build onto Spring server via Admin API
  --server-heartbeat-sec <N>   Native rolling session heartbeat period in seconds
```

---

## REST API сервера (`server/`)

Публичные эндпоинты клиента (`/api/v1`):
- `GET /api/v1/health` — статус сервера и открытый ключ X25519 (`serverPubHex`).
- `POST /api/v1/session/handshake` — X25519 + HKDF-SHA256 + HMAC handshake, возврат зашифрованных ChaCha20 долей `vmShare`/`vaultShare` и начального `rollingKey`.
- `POST /api/v1/session/heartbeat` — периодическое подтверждение сессии с проверкой `symDigest`/`jarDigest`/`hwid` и ротацией `rollingKey`.
- `POST /api/v1/session/logout` — завершение сессии.

Админ-эндпоинты (`/api/v1/admin`, заголовок `X-Admin-Token`):
- `POST /api/v1/admin/builds` — регистрация билда и секретных долей из манифеста.
- `POST /api/v1/admin/builds/{productId}/{buildId}/revoke` — отзыв конкретного билда.
- `POST /api/v1/admin/licenses` — выпуск лицензионного ключа (срок, лимит HWID, лимит одновременных сессий).
- `POST /api/v1/admin/licenses/{key}/revoke` — мгновенная блокировка ключа и всех активных сессий.
- `POST /api/v1/admin/licenses/{key}/reset-hwid` — сброс HWID-привязки.
- `GET /api/v1/admin/sessions` — список активных сессий.
- `GET /api/v1/admin/audit` — журнал событий безопасности и лицензирования.
