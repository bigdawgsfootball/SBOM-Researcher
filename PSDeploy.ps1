Deploy SBOMResearcher {
    By PSGalleryModule {
        FromSource SBOMResearcher
        To Artifactory
        WithOptions @{
            ApiKey = $env:ARTIFACTORY_TOKEN
        }
    }
}