# Deployment to Maven Central

Publishing the artifact to Maven Central through the 
[maven-release-plugin](http://maven.apache.org/maven-release/maven-release-plugin/) requires to be at a SNAPSHOT.

#### Preparation  
```bash
mvn release:clean release:prepare
```

#### Publishing the Artifact
```bash
mvn release:perform
```

1. [Open Staging Repositories](https://oss.sonatype.org/#stagingRepositories)
2. Select your staged project and press the **Close** button (top of the table)
3. If all requirements are fulfille, it will close and you can select **Refresh** and after selecting the project again: **Release**

It will take a little time until the released package appears in the maven central repository. 
