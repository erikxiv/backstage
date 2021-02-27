# Publishing a Schibsted-copy of a backstage plugin

1. Add `.npmrc` to plugin directory
1. Update package.json of plugin
1. Change `name` to `@aftonbladet/backstage-plugin...`
1. Add `"registry": "https://artifacts.schibsted.io/artifactory/api/npm/npm-virtual/"` to `publishConfig`

1) cd <backstage dir>
1) yarn install --frozen-lockfile
1) yarn tsc:full
1) cd <plugin dir>
1) yarn build
1) yarn publish

```
# .npmrc
registry=https://artifacts.schibsted.io/artifactory/api/npm/npm-virtual/
always-auth=true
email=${ARTIFACTORY_USER}
_auth=${ARTIFACTORY_NPM_SECRET}
# This is to force everyone to run on the same version of node and npm
engine-strict=true
@aftonbladet:registry=https://artifacts.schibsted.io/artifactory/api/npm/npm-virtual/
```
