# secretKey
## 概述
密钥使用的工具类  
包含AES、DES、RSA1、RSA2、SM2、SM4这几种，后续有其他新的加密算法会再加。
## 依赖包打包方式
```xml
<build>
<pluginManagement>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <configuration>
                <source>8</source>
                <target>8</target>
                <encoding>UTF-8</encoding>
            </configuration>
        </plugin>
        <!-- 要将源码放上去，需要加入这个插件 -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-source-plugin</artifactId>
            <version>3.1.0</version>
            <configuration>
                <attach>true</attach>
            </configuration>
            <executions>
                <execution>
                    <phase>compile</phase>
                    <goals>
                        <goal>jar</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</pluginManagement>
</build>
```
## CI
提交代码后通过github[工作流文件](./.github/workflows/maven.yml)持续集成.
```yml
name: Java CI with Maven

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]

jobs:
  build:

    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2
    - name: Set up JDK 8
      uses: actions/setup-java@v2
      with:
        java-version: '8'
        distribution: 'adopt'
        cache: maven
    - name: Build with Maven
      run: mvn -B package --file pom.xml
```
## maven打包

- 使用maven配置文件setting_toaliyun.xm发布不到[阿里云效](https://developer.aliyun.com/mvn/guide)
- 也可以使用maven配置文件setting_aliyun.xml发布到Github Packages,idea 的 mvn deploy。
- Github创建release时自动运行Github工作流[maven-publish](./.github/workflows/maven-publish.yml)自动打包。