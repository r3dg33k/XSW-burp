plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("org.bouncycastle:bcpkix-jdk18on:1.81")
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")

    implementation("xerces:xercesImpl:2.12.2")
    implementation("org.apache.santuario:xmlsec:4.0.4")
    implementation("com.google.guava:guava:33.5.0-jre")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}