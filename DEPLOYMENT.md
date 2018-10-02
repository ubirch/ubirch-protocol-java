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