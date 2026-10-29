"""Kapua source inventory at its reviewed corpus pin.

Measured from upstream POM and CucumberOptions declarations. This source-only
module holds the module and suite paths shared by the harness, strip and
closure index; it performs no Maven or Docker operation.
"""
from __future__ import annotations

from dataclasses import dataclass

SOURCE_COMMIT = "15c3c1e2c44f4a71885e2a16ed8c100c59e15091"


@dataclass(frozen=True)
class Suite:
    module: str
    runner_package: str
    upstream_runner_class: str
    glue_rel: str
    glue: tuple[str, ...]
    features: tuple[str, ...]

    @property
    def generated_package(self) -> str:
        return self.runner_package + ".r2t.generated"

    @property
    def generated_root(self) -> str:
        return (self.module + "/src/test/java/"
                + self.generated_package.replace(".", "/") + "/")


# All POM directories, including the root. Maven build output from any module
# is a possible compiled copy of removed glue and is purged at strip time.
MODULES = ('.',
 'assembly',
 'assembly/api',
 'assembly/broker-artemis',
 'assembly/console',
 'assembly/consumer',
 'assembly/consumer/lifecycle',
 'assembly/consumer/telemetry',
 'assembly/events-broker',
 'assembly/java-base',
 'assembly/java-base-17',
 'assembly/jetty-base',
 'assembly/job-engine',
 'assembly/service',
 'assembly/service/authentication',
 'assembly/sql',
 'broker',
 'broker/artemis',
 'broker/artemis/plugin',
 'build-tools',
 'client',
 'client/gateway',
 'client/gateway/api',
 'client/gateway/features',
 'client/gateway/features/karaf',
 'client/gateway/profile/kura',
 'client/gateway/provider',
 'client/gateway/provider/fuse',
 'client/gateway/provider/mqtt',
 'client/gateway/provider/paho',
 'client/gateway/spi',
 'client/security',
 'commons',
 'commons-rest',
 'commons-rest/errors',
 'commons-rest/filters',
 'commons-rest/model',
 'console',
 'console/core',
 'console/module',
 'console/module/about',
 'console/module/account',
 'console/module/api',
 'console/module/authentication',
 'console/module/authorization',
 'console/module/certificate',
 'console/module/data',
 'console/module/device',
 'console/module/endpoint',
 'console/module/job',
 'console/module/tag',
 'console/module/user',
 'console/module/welcome',
 'console/web',
 'consumer',
 'consumer/lifecycle',
 'consumer/lifecycle-app',
 'consumer/telemetry',
 'consumer/telemetry-app',
 'deployment',
 'deployment/commons',
 'deployment/docker',
 'deployment/minishift',
 'deployment/openshift',
 'dev-tools',
 'dev-tools/cucumber-reports',
 'extras',
 'extras/device-group-migrator',
 'extras/encryption-migrator',
 'extras/es-migrator',
 'extras/foreignkeys',
 'extras/liquibase-tool',
 'job-engine',
 'job-engine/api',
 'job-engine/app',
 'job-engine/app/core',
 'job-engine/app/resources',
 'job-engine/app/web',
 'job-engine/client',
 'job-engine/commons',
 'job-engine/jbatch',
 'locator',
 'locator/guice',
 'message',
 'message/api',
 'message/internal',
 'plug-ins',
 'plug-ins/sso',
 'plug-ins/sso/openid-connect',
 'plug-ins/sso/openid-connect/api',
 'plug-ins/sso/openid-connect/provider',
 'plug-ins/sso/openid-connect/provider-generic',
 'plug-ins/sso/openid-connect/provider-keycloak',
 'qa',
 'qa/common',
 'qa/integration',
 'qa/integration-steps',
 'qa/markers',
 'rest-api',
 'rest-api/core',
 'rest-api/resources',
 'rest-api/web',
 'service',
 'service/account',
 'service/account/api',
 'service/account/internal',
 'service/account/test',
 'service/account/test-steps',
 'service/api',
 'service/authentication',
 'service/authentication-app',
 'service/camel',
 'service/client',
 'service/commons',
 'service/commons/elasticsearch',
 'service/commons/elasticsearch/client-api',
 'service/commons/elasticsearch/client-rest',
 'service/commons/storable',
 'service/commons/storable/api',
 'service/commons/storable/internal',
 'service/commons/utils',
 'service/commons/utils/api',
 'service/commons/utils/internal',
 'service/datastore',
 'service/datastore/api',
 'service/datastore/internal',
 'service/datastore/test',
 'service/datastore/test-steps',
 'service/device',
 'service/device/api',
 'service/device/authentication',
 'service/device/call',
 'service/device/call/api',
 'service/device/call/kura',
 'service/device/commons',
 'service/device/management',
 'service/device/management/all',
 'service/device/management/all/api',
 'service/device/management/all/internal',
 'service/device/management/all/job',
 'service/device/management/api',
 'service/device/management/asset',
 'service/device/management/asset-store',
 'service/device/management/asset-store/api',
 'service/device/management/asset-store/dummy',
 'service/device/management/asset/api',
 'service/device/management/asset/internal',
 'service/device/management/asset/job',
 'service/device/management/bundle',
 'service/device/management/bundle/api',
 'service/device/management/bundle/internal',
 'service/device/management/bundle/job',
 'service/device/management/command',
 'service/device/management/command/api',
 'service/device/management/command/internal',
 'service/device/management/command/job',
 'service/device/management/configuration',
 'service/device/management/configuration-store',
 'service/device/management/configuration-store/api',
 'service/device/management/configuration-store/dummy',
 'service/device/management/configuration/api',
 'service/device/management/configuration/internal',
 'service/device/management/configuration/job',
 'service/device/management/configuration/message-api',
 'service/device/management/inventory',
 'service/device/management/inventory/api',
 'service/device/management/inventory/internal',
 'service/device/management/inventory/job',
 'service/device/management/job',
 'service/device/management/job/api',
 'service/device/management/job/internal',
 'service/device/management/keystore',
 'service/device/management/keystore/api',
 'service/device/management/keystore/internal',
 'service/device/management/keystore/job',
 'service/device/management/packages',
 'service/device/management/packages/api',
 'service/device/management/packages/internal',
 'service/device/management/packages/job',
 'service/device/management/registry',
 'service/device/management/registry/api',
 'service/device/management/registry/internal',
 'service/device/management/request',
 'service/device/management/request/api',
 'service/device/management/request/internal',
 'service/device/registry',
 'service/device/registry/api',
 'service/device/registry/internal',
 'service/device/registry/test',
 'service/device/registry/test-steps',
 'service/endpoint',
 'service/endpoint/api',
 'service/endpoint/internal',
 'service/endpoint/test-steps',
 'service/job',
 'service/job/api',
 'service/job/internal',
 'service/job/test',
 'service/job/test-steps',
 'service/scheduler',
 'service/scheduler/api',
 'service/scheduler/quartz',
 'service/scheduler/test',
 'service/scheduler/test-steps',
 'service/security',
 'service/security/authentication',
 'service/security/authentication/api',
 'service/security/authorization',
 'service/security/authorization/api',
 'service/security/certificate',
 'service/security/certificate/api',
 'service/security/certificate/internal',
 'service/security/registration',
 'service/security/registration/api',
 'service/security/registration/simple',
 'service/security/shiro',
 'service/security/test',
 'service/security/test-steps',
 'service/stream',
 'service/stream/api',
 'service/stream/internal',
 'service/system',
 'service/system/api',
 'service/system/internal',
 'service/system/test',
 'service/system/test-steps',
 'service/tag',
 'service/tag/api',
 'service/tag/internal',
 'service/tag/test',
 'service/tag/test-steps',
 'service/user',
 'service/user/api',
 'service/user/internal',
 'service/user/test',
 'service/user/test-steps',
 'simulator-kura',
 'translator',
 'translator/api',
 'translator/kapua',
 'translator/kapua/kura',
 'translator/kura',
 'translator/kura/jms',
 'translator/kura/mqtt',
 'translator/test',
 'translator/test-steps',
 'transport',
 'transport/api',
 'transport/jms',
 'transport/mqtt')

STEP_SOURCE_ROOTS = ('service/account/test-steps/src/main/java',
 'service/datastore/test-steps/src/main/java',
 'service/device/registry/test-steps/src/main/java',
 'service/endpoint/test-steps/src/main/java',
 'service/job/test-steps/src/main/java',
 'service/scheduler/test-steps/src/main/java',
 'service/security/test-steps/src/main/java',
 'service/system/test-steps/src/main/java',
 'service/tag/test-steps/src/main/java',
 'service/user/test-steps/src/main/java',
 'translator/test-steps/src/main/java')

# One row per upstream runner; feature membership and glue stay together.
SUITES = tuple(Suite(*row) for row in (('qa/integration',
  'org.eclipse.kapua.integration.service.account',
  'RunAccountServiceI9nTest',
  'service/account/test-steps/src/main/java/org/eclipse/kapua/service/account/steps',
  ('org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.service.authorization.steps',
   'org.eclipse.kapua.service.device.registry.steps',
   'org.eclipse.kapua.service.job.steps',
   'org.eclipse.kapua.service.tag.steps'),
  ('qa/integration/src/test/resources/features/account/AccountCredentialService.feature',
   'qa/integration/src/test/resources/features/account/AccountDeviceRegistryService.feature',
   'qa/integration/src/test/resources/features/account/AccountExpirationI9n.feature',
   'qa/integration/src/test/resources/features/account/AccountGroupService.feature',
   'qa/integration/src/test/resources/features/account/AccountJobService.feature',
   'qa/integration/src/test/resources/features/account/AccountRoleService.feature',
   'qa/integration/src/test/resources/features/account/AccountServiceCreation.feature',
   'qa/integration/src/test/resources/features/account/AccountTagService.feature',
   'qa/integration/src/test/resources/features/account/AccountUserService.feature',
   'qa/integration/src/test/resources/features/account/FindSelfAccount.feature')),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.authentication',
  'RunAuthenticationServiceI9nTest',
  'service/security/test-steps/src/main/java/org/eclipse/kapua/service/authorization/steps',
  ('org.eclipse.kapua.service.security.test',
   'org.eclipse.kapua.service.authorization.steps',
   'org.eclipse.kapua.service.authentication.steps',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.qa.common'),
  ('qa/integration/src/test/resources/features/authentication/UserCredentialServiceUnitTests.feature',)),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.authorization',
  'RunAuthorizationServiceI9nTest',
  'service/security/test-steps/src/main/java/org/eclipse/kapua/service/authorization/steps',
  ('org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.authorization.steps',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.service.device.registry.steps'),
  ('qa/integration/src/test/resources/features/authorization/AccessInfoService.feature',
   'qa/integration/src/test/resources/features/authorization/DomainService.feature',
   'qa/integration/src/test/resources/features/authorization/GroupService.feature',
   'qa/integration/src/test/resources/features/authorization/MiscAuthorization.feature',
   'qa/integration/src/test/resources/features/authorization/RoleService.feature')),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.user',
  'RunLockoutExpirationI9nTest',
  'service/account/test-steps/src/main/java/org/eclipse/kapua/service/account/steps',
  ('org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.service.user.steps'),
  ('qa/integration/src/test/resources/features/user/LockoutExpirationI9n.feature',)),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.user',
  'RunTenantSEI9nTest',
  'service/account/test-steps/src/main/java/org/eclipse/kapua/service/account/steps',
  ('org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.service.user.steps'),
  ('qa/integration/src/test/resources/features/user/TenantSEI9n.feature',)),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.user',
  'RunUserCredentialsI9nTest',
  'service/account/test-steps/src/main/java/org/eclipse/kapua/service/account/steps',
  ('org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.service.authorization.steps'),
  ('qa/integration/src/test/resources/features/user/UserCredentialsI9n.feature',)),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.user',
  'RunUserMfaUnitTest',
  'service/security/test-steps/src/main/java/org/eclipse/kapua/service/authorization/steps',
  ('org.eclipse.kapua.service.security.test',
   'org.eclipse.kapua.service.authorization.steps',
   'org.eclipse.kapua.service.authentication.steps',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.qa.common'),
  ('qa/integration/src/test/resources/features/user/UserMfaUnitTests.feature',)),
 ('qa/integration',
  'org.eclipse.kapua.integration.service.user',
  'RunUserProfileUnitTests',
  'service/security/test-steps/src/main/java/org/eclipse/kapua/service/authorization/steps',
  ('org.eclipse.kapua.service.security.test',
   'org.eclipse.kapua.service.authorization.steps',
   'org.eclipse.kapua.service.authentication.steps',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.qa.common'),
  ('qa/integration/src/test/resources/features/user/UserProfileUnitTests.feature',)),
 ('service/account/test',
  'org.eclipse.kapua.service.account.test',
  'RunAccountUnitTest',
  'service/account/test-steps/src/main/java/org/eclipse/kapua/service/account/steps',
  ('org.eclipse.kapua.service.account.steps',
   'org.eclipse.kapua.service.account.test',
   'org.eclipse.kapua.qa.common'),
  ('service/account/test/src/test/resources/features/AccountService.feature',)),
 ('service/device/registry/test',
  'org.eclipse.kapua.service.device.registry.test',
  'RunDeviceRegistryUnitTest',
  'service/device/registry/test-steps/src/main/java/org/eclipse/kapua/service/device/registry/steps',
  ('org.eclipse.kapua.service.device.registry.test',
   'org.eclipse.kapua.service.device.registry.steps',
   'org.eclipse.kapua.qa.common'),
  ('service/device/registry/test/src/test/resources/features/DeviceEvent.feature',
   'service/device/registry/test/src/test/resources/features/DeviceRegistry.feature',
   'service/device/registry/test/src/test/resources/features/DeviceRegistryConnection.feature',
   'service/device/registry/test/src/test/resources/features/DeviceRegistryValidation.feature')),
 ('service/job/test',
  'org.eclipse.kapua.service.job.test',
  'RunJobUnitTest',
  'service/job/test-steps/src/main/java/org/eclipse/kapua/service/job/steps',
  ('org.eclipse.kapua.service.job.test',
   'org.eclipse.kapua.service.job.steps',
   'org.eclipse.kapua.qa.common'),
  ('service/job/test/src/test/resources/features/JobService.feature',
   'service/job/test/src/test/resources/features/JobStepDefinitionService.feature',
   'service/job/test/src/test/resources/features/JobStepService.feature')),
 ('service/scheduler/test',
  'org.eclipse.kapua.service.scheduler.test',
  'RunSchedulerUnitTest',
  'service/scheduler/test-steps/src/main/java/org/eclipse/kapua/service/scheduler/steps',
  ('org.eclipse.kapua.service.scheduler.test',
   'org.eclipse.kapua.service.scheduler.steps',
   'org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.job.steps'),
  ('service/scheduler/test/src/test/resources/features/SchedulerService.feature',)),
 ('service/security/test',
  'org.eclipse.kapua.service.security.test',
  'RunSecurityUnitTest',
  'service/security/test-steps/src/main/java/org/eclipse/kapua/service/authorization/steps',
  ('org.eclipse.kapua.service.security.test',
   'org.eclipse.kapua.service.authorization.steps',
   'org.eclipse.kapua.service.authentication.steps',
   'org.eclipse.kapua.qa.common'),
  ('service/security/test/src/test/resources/features/CredentialServiceUnitTests.feature',
   'service/security/test/src/test/resources/features/GroupServiceUnitTests.feature',
   'service/security/test/src/test/resources/features/RoleServiceUnitTests.feature')),
 ('service/system/test',
  'org.eclipse.kapua.service.systeminfo.test',
  'RunSystemInfoUnitTest',
  'service/device/registry/test-steps/src/main/java/org/eclipse/kapua/service/device/registry/steps',
  ('org.eclipse.kapua.service.device.registry.steps',
   'org.eclipse.kapua.service.systeminfo.test',
   'org.eclipse.kapua.service.systeminfo.steps',
   'org.eclipse.kapua.qa.common'),
  ('service/system/test/src/test/resources/features/SystemInfoServiceUnitTests.feature',)),
 ('service/tag/test',
  'org.eclipse.kapua.service.tag.test',
  'RunTagUnitTest',
  'service/device/registry/test-steps/src/main/java/org/eclipse/kapua/service/device/registry/steps',
  ('org.eclipse.kapua.service.device.registry.steps',
   'org.eclipse.kapua.service.tag.test',
   'org.eclipse.kapua.service.tag.steps',
   'org.eclipse.kapua.qa.common'),
  ('service/tag/test/src/test/resources/features/TagService.feature',)),
 ('service/user/test',
  'org.eclipse.kapua.service.user.test',
  'RunUserUnitTest',
  'service/user/test-steps/src/main/java/org/eclipse/kapua/service/user/steps',
  ('org.eclipse.kapua.service.user.test',
   'org.eclipse.kapua.service.user.steps',
   'org.eclipse.kapua.qa.common'),
  ('service/user/test/src/test/resources/features/UserService.feature',)),
 ('translator/test',
  'org.eclipse.kapua.translator.test',
  'RunTranslatorUnitTest',
  'service/device/registry/test-steps/src/main/java/org/eclipse/kapua/service/device/registry/steps',
  ('org.eclipse.kapua.translator.test',
   'org.eclipse.kapua.qa.common',
   'org.eclipse.kapua.service.device.registry.steps'),
  ('translator/test/src/test/resources/features/TranslatorUnitTests.feature',))))

# Held by the judge for an Elasticsearch-dependency probe. This binding makes
# that diagnostic executable; it is deliberately outside the admitted map.
DIAGNOSTIC_SUITES = (Suite(
    module="qa/integration",
    runner_package="org.eclipse.kapua.integration.service.datastore",
    upstream_runner_class="RunDatastoreTransportI9nTest",
    glue_rel="service/datastore/test-steps/src/main/java/org/eclipse/kapua/service/datastore/steps",
    glue=('org.eclipse.kapua.qa.common', 'org.eclipse.kapua.qa.integration.steps', 'org.eclipse.kapua.service.account.steps', 'org.eclipse.kapua.service.datastore.steps', 'org.eclipse.kapua.service.user.steps', 'org.eclipse.kapua.service.device.registry.steps'),
    features=('qa/integration/src/test/resources/features/datastore/DatastoreMetricStore.feature',)),)

FEATURE_SUITES = {feature: suite for suite in SUITES for feature in suite.features}
TEST_MODULES = tuple(sorted({suite.module for suite in SUITES}))
TEST_SOURCE_ROOTS = STEP_SOURCE_ROOTS + (
    "qa/common/src/main/java", "qa/integration-steps/src/main/java",
) + tuple(module + "/src/test/java" for module in TEST_MODULES)


def module_path(module: str, path: str) -> str:
    return path if module == "." else module + "/" + path


# The original source trees and POMs are substrate; target/ never is. The
# generated per-item feature is the sole volatile source file in each module.
SUBSTRATE_ROOTS = tuple(path for module in MODULES
                        for path in (module_path(module, "src"),
                                     module_path(module, "pom.xml")))
BUILD_ROOTS = tuple(module_path(module, "target") for module in MODULES)
FEATURE_PATHS = tuple(module + "/src/test/resources/_bench_item.feature"
                      for module in TEST_MODULES)
SOURCE_ROOTS = tuple(module_path(module, "src/main/java") for module in MODULES)

# Installed glue artifacts must not retain an earlier candidate after its
# source is removed. These artifactIds are the direct POM declarations.
STEP_ARTIFACTS = ('kapua-account-test-steps', 'kapua-datastore-test-steps', 'kapua-device-registry-test-steps', 'kapua-endpoint-test-steps', 'kapua-job-test-steps', 'kapua-scheduler-test-steps', 'kapua-security-test-steps', 'kapua-system-test-steps', 'kapua-tag-test-steps', 'kapua-user-test-steps', 'kapua-translator-test-steps')


def feature_items(repo_root: str, *, scaffolding: bool = False) -> list:
    """The admitted source items, excluding setup/teardown from the population.

    Exact feature membership comes from native runners. Infrastructure scenarios
    remain available to compare full native pickle sets, never as paid items.
    """
    import os
    from ..core.gherkin import parse_feature_file

    items = []
    for relative in sorted(FEATURE_SUITES):
        feature = parse_feature_file(os.path.join(repo_root, relative),
                                     allow_tag_gaps=True)
        for scenario in feature.scenarios:
            if not scaffolding and {"@setup", "@teardown"}.intersection(
                    feature.tags + scenario.tags):
                continue
            items.append((f"kapua/{relative}:{scenario.line}", feature, scenario))
    return items


def capture_path(artifacts: str, suite: Suite, *, stripped: bool = False) -> str:
    """One untouched native JSON per runner; native plugin names can collide."""
    import os

    name = "cucumber_stripped_dry_run.json" if stripped else "cucumber_dry_run.json"
    return os.path.join(artifacts, "kapua",
                        suite.runner_package + "." + suite.upstream_runner_class,
                        name)


def code_source_map(repo_root: str, boundary, *, workdir: str = "/work",
                    maven_repository: str = "/opt/m2") -> str:
    """Bind this pinned reactor's output origins to original source modules.

    Its 250 POMs have literal direct artifactIds and literal direct or immediate
    parent group/version fields. The native classpath/JAR census checks these
    origins against the installed artifacts; no package-prefix inference is used.
    """
    import os
    from ..core.boundary import PRODUCTION

    mappings = {}
    for (group, artifact, version), entry in reactor_coordinates(repo_root).items():
        module = entry["module"]
        source = module_path(module, "src/main/java")
        production = any(boundary.classify(os.path.relpath(os.path.join(base, name),
                                repo_root).replace(os.sep, "/")) == PRODUCTION
                         for base, _, files in os.walk(os.path.join(repo_root, source))
                         for name in files if name.endswith(".java"))
        mappings[workdir.rstrip("/") + "/" + module_path(module, "target/classes")] = (
            source, "production" if production else "test")
        mappings[workdir.rstrip("/") + "/" + module_path(module, "target/test-classes")] = (
            module_path(module, "src/test/java"), "test")
        if entry["packaging"] in ("jar", "bundle"):
            jar = (maven_repository.rstrip("/") + "/" + group.replace(".", "/")
                   + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".jar")
            if jar in mappings:
                raise ValueError(f"duplicate Kapua code source {jar}")
            mappings[jar] = (source, "production" if production else "test")
    return ("r2t.java-code-sources/1\t" + workdir.rstrip("/") + "\n"
            + "".join(code + "\t" + root + "\t" + role + "\n"
                      for code, (root, role) in sorted(mappings.items())))


def reactor_coordinates(repo_root: str) -> dict:
    """Read the pin's literal GAVs; refuse unresolved or duplicate coordinates."""
    import os
    import xml.etree.ElementTree as ET

    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    coordinates = {}
    for module in MODULES:
        pom = ET.parse(os.path.join(repo_root, module, "pom.xml")).getroot()
        def field(name):
            return (pom.findtext("m:" + name, namespaces=ns) or
                    pom.findtext("m:parent/m:" + name, namespaces=ns))
        gav = (field("groupId"), pom.findtext("m:artifactId", namespaces=ns), field("version"))
        if any(not value or "${" in value for value in gav) or gav in coordinates:
            raise ValueError(f"{module}: unresolved or duplicate Kapua reactor GAV {gav}")
        coordinates[gav] = {"module": module,
            "packaging": pom.findtext("m:packaging", namespaces=ns) or "jar"}
    return coordinates


def verify_code_source_classpath(repo_root: str, suite: Suite, classpath: str,
                                 mapping: str, *, workdir: str = "/work",
                                 maven_repository: str = "/opt/m2") -> dict:
    """Join actual ordered Surefire origins to the reactor map before API use.

    A single trailing separator is the measured Surefire spelling. Additional
    empty entries, substituted module outputs and unmapped first-party versions
    or classifiers refuse instead of silently shrinking direct-call collection.
    """
    import hashlib

    entries = (classpath[:-1] if classpath.endswith(":") else classpath).split(":")
    if any(not entry or not entry.startswith("/") for entry in entries) or len(set(entries)) != len(entries):
        raise ValueError("Kapua Surefire classpath has empty, relative or duplicate entries")
    expected_outputs = [workdir.rstrip("/") + "/" + suite.module + "/target/" + name
                        for name in ("test-classes", "classes")]
    if entries[:2] != expected_outputs or [entry for entry in entries if entry.startswith(workdir.rstrip("/") + "/")] != expected_outputs:
        raise ValueError("Kapua Surefire classpath has the wrong module outputs")
    lines = mapping.splitlines()
    if not lines or lines[0] != "r2t.java-code-sources/1\t" + workdir.rstrip("/"):
        raise ValueError("Kapua code-source map has the wrong workspace")
    origins = {}
    for line in lines[1:]:
        row = line.split("\t")
        if len(row) != 3 or row[0] in origins:
            raise ValueError("Kapua code-source map has invalid or duplicate rows")
        origins[row[0]] = {"source_root": row[1], "role": row[2]}
    coordinates = reactor_coordinates(repo_root)
    owned = {(group, artifact) for group, artifact, _ in coordinates}
    relevant = list(expected_outputs)
    expected_roots = dict(zip(expected_outputs,
        [suite.module + "/src/test/java", suite.module + "/src/main/java"]))
    for entry in entries[2:]:
        prefix = maven_repository.rstrip("/") + "/"
        if not entry.startswith(prefix) or not entry.endswith(".jar"):
            raise ValueError(f"unmeasured Kapua classpath entry {entry}")
        parts = entry[len(prefix):].split("/")
        if len(parts) < 4:
            raise ValueError(f"invalid Maven classpath path {entry}")
        group, artifact, version, name = (".".join(parts[:-3]), parts[-3], parts[-2], parts[-1])
        if (group, artifact) not in owned:
            continue
        coordinate = (group, artifact, version)
        if coordinate not in coordinates or name != artifact + "-" + version + ".jar":
            raise ValueError(f"unmapped Kapua version or classifier {entry}")
        relevant.append(entry)
        expected_roots[entry] = module_path(coordinates[coordinate]["module"], "src/main/java")
    verified = []
    for entry in relevant:
        if entry not in origins:
            raise ValueError(f"Kapua actual code source is unmapped: {entry}")
        if origins[entry]["source_root"] != expected_roots[entry] or origins[entry]["role"] not in ("production", "test"):
            raise ValueError(f"Kapua actual code source maps to the wrong source module: {entry}")
        verified.append({"code_source": entry, **origins[entry]})
    return {"map_sha256": hashlib.sha256(mapping.encode("utf-8")).hexdigest(),
            "classpath_entries": len(entries), "first_party_jars": len(relevant) - 2,
            "verified_origins": verified}
