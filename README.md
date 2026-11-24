# neuro-fabric-native-obfuscator

Нативный **Java-to-C++ (J2C -> `.dll`)** обфускатор и гибридный протектор с полиморфной зашифрованной **Native VM**, разработанный специально для модов **Minecraft Fabric**.

Переносит Java-байткод в нативную Windows x64 `.dll`, шифрует классы в `.fucked` с нативной подгрузкой через JNI `DefineClass`, встраивает DLL прямо в папку `natives/` внутри мода и маскирует структуру архива сотнями мусорных классов и папок.

---

## Основные возможности

### Нативная компиляция и VM
- **Java -> C++20 -> Windows x64 `.dll`**: преобразование методов, конструкторов (тело после `super(...)`), `<clinit>`, лямбд (`invokedynamic`), `StringConcatFactory` и `record` в нативный код.
- **Control-Flow Flattening (CFF) + MBA + Opaque Predicates**:
  - разбиение кода на перемешанные базовые блоки с нелинейной state-машиной;
  - Mixed Boolean-Arithmetic (MBA) синтез констант и арифметики, привязанный к `volatile` runtime-энтропии;
  - ложные (bogus) мёртвые ветки и непрозрачные предикаты.
- **Полиморфная зашифрованная Native VM (`--tier ULTRA` / `--vm`)**:
  - уникальная перестановка 256 опкодов при каждой сборке;
  - шифрование байткода потоковым ключом (`SplitMix64`);
  - собственный стеково-слотовый интерпретатор внутри `.dll` с поддержкой исключений и `RefTable`.
- **Zero-Export `RegisterNatives`**: `.dll` экспортирует **только `JNI_OnLoad`** — в таблице экспортов нет ни одного `Java_*` символа.
- **Bit-Exact Intrinsics & `RefTable`**: быстрые интринсики для `Math.*`, `Integer.*`, `Long.*`, `Float.*`, `Double.*` без лишних JNI-вызовов и безопасное управление `LocalRef` с подсчётом ссылок для длинных игровых циклов.

### Интеграция с Minecraft Fabric
- **Авторазбор `fabric.mod.json` и `*.mixins.json`**: автоматическое определение пакетов мода и сохранение контрактов entrypoints и Mixin.
- **Безопасная защита `@Mixin` (`MixinOutliner`)**: хуки `@Inject`, `@Overwrite`, `@Redirect`, `@Modify*` выносятся в нативный bridge-класс внутри `.dll` с динамическим разрешением `@Shadow`-полей и методов на целевом классе, а в `@Mixin` остаётся минимальный трамплин, совместимый со SpongePowered Mixin.
- **Поддержка `KnotClassLoader`**: разрешение классов работает через `FindClass` с автоматическим fallback на `Class.forName(..., true, modLoader)`.
- **Встроенная папка `natives/`**: готовая `.dll` упаковывается в `natives/<name>.dll` прямо внутри итогового `.jar` и автоматически загружается при старте мода без дополнительных флагов JVM.

### Защита архива и самозащита
- **Шифрование классов в `.fucked`**: классы логики и Mixin-мосты удаляются как `.class`, шифруются без заголовка (индивидуальный ключ + FNV-1a-64 MAC) и прячутся в случайных путях `.fucked`. Расшифровка и загрузка через JNI `DefineClass` выполняются только внутри `.dll` с последующим затиранием памяти (`secure_wipe`).
- **Мусорные классы и папки (`--junk`)**: генерация десятков глубоко вложенных фейковых пакетов с валидными мусорными `.class` (switch, try/catch, фейковые строки и native-заглушки) и неотличимыми по энтропии `.fucked`-пустышками.
- **Шифрованное хранилище символов и строк**: имена классов, методов, полей, дескрипторы и UTF-16 строковые литералы зашифрованы в `.dll`, расшифровываются на стеке и немедленно затираются; кэши `jclass`/`jmethodID`/`jfieldID` замаскированы runtime cookie.
- **Anti-Debug / Anti-Dump / Anti-Hook / Anti-Tamper**:
  - динамический поиск Win32 API через PEB (`InMemoryOrderModuleList` + FNV-1a экспорты, без явных импортов `IsDebuggerPresent` / `NtQueryInformationProcess`);
  - проверки PEB (`BeingDebugged`, `NtGlobalFlag`, флаги `jdwp` в командной строке), `NtQueryInformationProcess`, аппаратных точек останова (`Dr0..Dr3`);
  - проверка JNI-таблицы на перехват за пределами `jvm.dll`, а также проверка целостности таблицы символов `.dll` и ресурсов внутри `.jar`.

---

## Требования

- **Windows x64**
- **JDK 21+** (с `include/jni.h` и `include/win32/jni_md.h`)
- **MinGW-W64 `g++` (UCRT x86_64, C++20)** в `PATH` (или указанный через `--compiler`)

---

## Быстрый старт

### 1. Сборка и запуск автотестов
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File hydro.ps1 test
```
Скрипт скомпилирует протектор в `build\hydro-j2c.jar`, соберёт тестовый Fabric-мод, прогонит защиту в режимах `STRONG` и `ULTRA`, проверит таблицу экспортов `.dll`, структуру `natives/` и `.fucked` и выполнит проверку в изолированном `ClassLoader` с симуляцией Mixin и тестом Anti-Tamper.

### 2. Сборка fat JAR и библиотеки аннотаций
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File hydro.ps1 build
```
После сборки появятся:
- `build\hydro-j2c.jar` — сам протектор;
- `build\neuro-annotations.jar` — аннотации `@Native`, `@NotNative`, `@NativeVM` для подключения в мод (`compileOnly`).

### 3. Защита Fabric-мода

**Режим аннотаций (`-a` / `--annotations`, как в `native-obfuscator`)** — в `.dll` уйдут только классы и методы с `@Native` / `@NativeVM` (включая их лямбды и `@Mixin`-хуки), остальной код останется нетронутым Java-байткодом:
```java
import dev.neuro.nativeobfuscator.Native;
import dev.neuro.nativeobfuscator.NotNative;
import dev.neuro.nativeobfuscator.NativeVM;

@Native
public class AuthManager {
    public boolean checkLicense(String key) { ... } // уйдёт в .dll как CFF+MBA native

    @NativeVM
    public byte[] decryptPayload(byte[] data) { ... } // уйдёт в полиморфную Native VM

    @NotNative
    public String getVersion() { return "1.0"; } // останется в Java
}
```
> Поддерживаются также аннотации `by.radioegor146.nativeobfuscator.Native` и `NotNative` — в итоговом JAR все маркеры аннотаций автоматически вычищаются.

Запуск с `-a`:
```powershell
java -jar build\hydro-j2c.jar -a -i my-mod.jar -o my-mod-protected.jar --tier STRONG
```

**Полная защита всего мода (`STRONG`)** (без `-a`, максимальная производительность CFF + MBA + Opaque Predicates, `.fucked`-классы, `natives/*.dll` внутри JAR):
```powershell
java -jar build\hydro-j2c.jar -i my-mod.jar -o my-mod-protected.jar --tier STRONG
```

**Режим `ULTRA`** (CFF+MBA + полиморфная Native VM для выбранных или всех подходящих методов):
```powershell
java -jar build\hydro-j2c.jar -i my-mod.jar -o my-mod-protected.jar --tier ULTRA --vm "com/example/auth/**" --vm-exclude "com/example/render/**"
```

---

## Параметры CLI

| Параметр | Описание | По умолчанию |
|---|---|---|
| `-i, --input <jar>` | Входной `.jar` файл мода | Обязательно |
| `-o, --output <jar>` | Выходной защищённый `.jar` | `<name>-protected.jar` |
| `-d, --dll <dll>` | Путь для сохранения `.dll` на диск | Рядом с выходным JAR |
| `-a, --annotations` | Переносить в `.dll` только `@Native` / `@NativeVM` (учитывать `@NotNative`) | Выкл (защищаются все классы мода) |
| `-w, --white-list <file>` | Whitelist файл со списком классов/масок | — |
| `-b, --black-list <file>` | Blacklist файл со списком исключений | — |
| `--tier <FAST\|STRONG\|ULTRA>` | Уровень защиты (`ULTRA` включает Native VM) | `STRONG` |
| `--include <glob>` | Маска включаемых классов/пакетов | Авто из `fabric.mod.json` |
| `--exclude <glob>` | Маска исключаемых классов/пакетов | — |
| `--vm <glob>` | Принудительно поместить классы/методы в Native VM | — |
| `--vm-exclude <glob>` | Оставить классы/методы в быстром CFF C++ вместо VM | — |
| `--junk <N>` | Количество мусорных `.class` и `.fucked` файлов | `300` |
| `--no-junk` | Отключить генерацию мусора | — |
| `--no-fucked` | Не шифровать классы в `.fucked` | — |
| `--external-dll [path]` | Загружать внешнюю `.dll` с диска вместо `natives/` | Выкл (используется `natives/`) |
| `--encrypt-dll` | Дополнительно шифровать `.dll` внутри `natives/` | Выкл |
| `--no-mixins` | Отключить авто-вынос `@Mixin` хуков | Выкл |
| `--no-ctor-outline` | Отключить вынос тела `<init>` / `<clinit>` | Выкл |
| `--no-anti-debug` | Отключить анти-отладку | Выкл |
| `--no-anti-dump` | Отключить анти-дамп / проверку JNI vtable | Выкл |
| `--no-anti-tamper` | Отключить проверку целостности `.dll` и `.jar` | Выкл |
| `-j, --jobs <N>` | Количество потоков компиляции C++ | По числу ядер CPU |
| `--jdk <path>` | Путь к JDK с `jni.h` | Автопоиск |
| `--compiler <path>` | Путь к `g++` | `g++` |
| `--seed <num>` | Фиксированный seed генерации | Случайный |

---

## Важные примечания по совместимости с Fabric

- Классы, указанные в `fabric.mod.json` в секции `entrypoints`, остаются в `.class` как пустые нативные обёртки без бизнес-логики внутри байткода, чтобы Fabric Loader мог их инициализировать.
- Классы `@Mixin` сохраняют 1-строчный трамплин, вызывающий нативный bridge-класс (который компилируется в `.dll` и шифруется в `.fucked`), благодаря чему SpongePowered Mixin корректно применяет трансформации.
- Скомпилированная `.dll` нацелена на **Windows x64** (x86_64) и линкуется статически без зависимостей от `libstdc++-6.dll` или `libgcc_s_seh-1.dll`.
