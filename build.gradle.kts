plugins {
    java
    application
}

group = "dev.hydro"
version = "1.0.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    implementation(fileTree("libs") { include("*.jar") })
}

application {
    mainClass.set("dev.hydro.j2c.Main")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "dev.hydro.j2c.Main"
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
}
