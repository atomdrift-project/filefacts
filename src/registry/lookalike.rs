//! Lookalike names: a registry record whose name sits one keystroke from a
//! popular package's, without being it.
//!
//! Only Terraform for now. A provider is `namespace/type`, and the type names
//! what it manages, so a squat keeps the type and bends the namespace:
//! `kreuzwenker/docker` for `kreuzwerker/docker`. Comparing namespaces within
//! one type is what keeps this quiet. Measured 2026-09-24 over all 7,320
//! providers against this list, it flagged exactly one — that squat — while two
//! edits already caught a legitimate fork (`cnrancher/rancher2`), and a
//! different namespace reusing a popular type is ordinary (1,498 providers).

use std::cmp::Ordering;

/// The 300 most-downloaded Terraform providers, lowercased and sorted, from
/// 2026-09-24. Regenerate with:
///
/// ```sh
/// for p in 1 2 3; do curl -s "https://registry.terraform.io/v2/providers?page%5Bsize%5D=100&page%5Bnumber%5D=$p&sort=-downloads"; done |
///   jq -r '.data[].attributes|"\(.namespace)/\(.name)"|ascii_downcase' | LC_ALL=C sort -u
/// ```
///
/// Popularity at this depth moves slowly, and a stale entry costs nothing: a
/// provider that fell out of the top 300 is still worth impersonating.
const TERRAFORM_POPULAR: &[&str] = &[
    "1password/onepassword",
    "aaronfeng/aws",
    "adamcoulteroz/azurehelpers",
    "aidanmelen/snowsql",
    "airbytehq/airbyte",
    "aiven/aiven",
    "akamai/akamai",
    "akeyless-community/akeyless",
    "alekc/kubectl",
    "alexkappa/auth0",
    "aliyun/alicloud",
    "alxrem/jsonnet",
    "aminueza/minio",
    "anschoewe/curl",
    "ansible/ansible",
    "aptible/aptible",
    "argoproj-labs/argocd",
    "athenz/athenz",
    "auth0/auth0",
    "aviatrixsystems/aviatrix",
    "aztfmod/azurecaf",
    "azure/azapi",
    "azure/modtm",
    "bangau1/mysql",
    "banzaicloud/k8s",
    "betr-io/mssql",
    "betterstackhq/better-uptime",
    "bouk/ejson",
    "bpg/proxmox",
    "brainly/redshift",
    "buildkite/buildkite",
    "bunnyway/bunnynet",
    "bwoznicki/assert",
    "camptocamp/jwt",
    "carlpett/sops",
    "castai/castai",
    "chainguard-dev/apko",
    "chainguard-dev/chainguard",
    "chainguard-dev/cosign",
    "chainguard-dev/helm",
    "chainguard-dev/imagetest",
    "chainguard-dev/oci",
    "checkly/checkly",
    "checkpointsw/checkpoint",
    "chilicat/pkcs12",
    "chronosphereio/chronosphere",
    "ciscodevnet/aci",
    "ciscodevnet/mso",
    "citrix/citrixadc",
    "civo/civo",
    "clickhouse/clickhouse",
    "cloudamqp/cloudamqp",
    "cloudflare/cloudflare",
    "cloudfoundry-community/cloudfoundry",
    "cloudposse/awsutils",
    "cloudposse/template",
    "cloudposse/utils",
    "cockroachdb/cockroach",
    "coder/coder",
    "coder/coderd",
    "community-terraform-providers/ignition",
    "confluentinc/confluent",
    "coralogix/coralogix",
    "cox-automotive/alks",
    "cycloidio/cycloid",
    "cyralinc/cyral",
    "cyrilgdn/postgresql",
    "cyrilgdn/rabbitmq",
    "databricks/databricks",
    "datadog/datadog",
    "datadrivers/nexus",
    "datastax/astra",
    "davidji99/herokux",
    "denouche/awx",
    "deviavir/gsuite",
    "devops-rob/terracurl",
    "devoteamgcloud/looker",
    "digitalocean/digitalocean",
    "dmachard/http-client",
    "dmacvicar/libvirt",
    "dnsimple/dnsimple",
    "dome9/dome9",
    "dopplerhq/doppler",
    "drfaust92/bitbucket",
    "duplocloud/duplocloud",
    "dynatrace-oss/dynatrace",
    "e-breuninger/netbox",
    "eddycharly/kops",
    "edge-center/edgecenter",
    "elastic-infra/ldap",
    "elastic/ec",
    "elastic/elasticstack",
    "env0/env0",
    "eppo/environment",
    "equinix/equinix",
    "exoscale/exoscale",
    "f5networks/bigip",
    "fastly/fastly",
    "ferlab-ste-justine/etcd",
    "ferlab-ste-justine/minio",
    "ferlab-ste-justine/netaddr",
    "ferlab-ste-justine/opensearch",
    "ferlab-ste-justine/patroni",
    "fgouteroux/mimir",
    "figma/aws",
    "fivetran/fivetran",
    "flexibleenginecloud/flexibleengine",
    "fluxcd/flux",
    "fmontezuma/restapi",
    "fortinetdev/fortios",
    "g-core/gcore",
    "g-core/gcorelabs",
    "gavinbunney/kubectl",
    "gitlabhq/gitlab",
    "glesys/glesys",
    "goauthentik/authentik",
    "goharbor/harbor",
    "gpsinsight/fusionauth",
    "grafana/grafana",
    "groundcover-com/groundcover",
    "harness/harness",
    "hashicorp/ad",
    "hashicorp/archive",
    "hashicorp/aws",
    "hashicorp/awscc",
    "hashicorp/azuread",
    "hashicorp/azurerm",
    "hashicorp/boundary",
    "hashicorp/cloudinit",
    "hashicorp/consul",
    "hashicorp/dns",
    "hashicorp/external",
    "hashicorp/google",
    "hashicorp/google-beta",
    "hashicorp/googleworkspace",
    "hashicorp/hcp",
    "hashicorp/helm",
    "hashicorp/http",
    "hashicorp/kubernetes",
    "hashicorp/local",
    "hashicorp/nomad",
    "hashicorp/null",
    "hashicorp/random",
    "hashicorp/template",
    "hashicorp/tfe",
    "hashicorp/time",
    "hashicorp/tls",
    "hashicorp/vault",
    "heroku/heroku",
    "hetznercloud/hcloud",
    "honeycombio/honeycombio",
    "hpe/hpegl",
    "ibm-cloud/ibm",
    "imperva/incapsula",
    "incident-io/incident",
    "infobloxopen/infoblox",
    "instaclustr/instaclustr",
    "integrations/github",
    "ionos-cloud/ionoscloud",
    "isobit/util",
    "isometry/deepmerge",
    "iterative/iterative",
    "ivoronin/macaddress",
    "jdamata/sonarqube",
    "jeremmfr/iptables",
    "jfrog/artifactory",
    "jfrog/platform",
    "jfrog/project",
    "jianyuan/sentry",
    "juju/juju",
    "k-yomo/algolia",
    "kaginari/mongodb",
    "kbst/kustomization",
    "keycloak/keycloak",
    "ko-build/ko",
    "kong/konnect",
    "kreuzwerker/docker",
    "l-with/ldap",
    "labd/commercetools",
    "lacework/lacework",
    "launchdarkly/launchdarkly",
    "linode/linode",
    "loafoe/htpasswd",
    "loafoe/ssh",
    "logdna/logdna",
    "logzio/logzio",
    "lukasaron/stripe",
    "magodo/restful",
    "mastercard/restapi",
    "maxlaverse/bitwarden",
    "megaport/megaport",
    "meilleursagents/ansiblevault",
    "metio/git",
    "microsoft/azuredevops",
    "microsoft/msgraph",
    "mongey/confluentcloud",
    "mongey/kafka",
    "mongey/kafka-connect",
    "mongodb/mongodbatlas",
    "mrolla/circleci",
    "mrparkers/keycloak",
    "mumoshu/eksctl",
    "mypurecloud/genesyscloud",
    "nats-io/jetstream",
    "nekottyo/jsonschema",
    "netapp/netapp-cloudmanager",
    "newrelic/newrelic",
    "nikolalohinski/jinja",
    "nitrikx/postgresql",
    "ns1-terraform/ns1",
    "nullstone-io/dockerless",
    "nutanix/nutanix",
    "octopusdeploylabs/octopusdeploy",
    "okta/okta",
    "opennebula/opennebula",
    "opensearch-project/opensearch",
    "opentelekomcloud/opentelekomcloud",
    "opsgenie/opsgenie",
    "oracle/oci",
    "ouest-france/ldap",
    "outscale/outscale",
    "ovh/mimirtool",
    "ovh/ovh",
    "pablovarela/slack",
    "pagerduty/pagerduty",
    "paloaltonetworks/panos",
    "paloaltonetworks/prismacloud",
    "pan-net/powerdns",
    "paultyng/sql",
    "paultyng/unifi",
    "petoju/mysql",
    "pgssoft/mssql",
    "philips-software/hsdp",
    "phillbaker/elasticsearch",
    "plukevdh/dmsnitch",
    "port-labs/port-labs",
    "poseidon/ct",
    "rancher/rancher2",
    "rancher/rke",
    "redislabs/rediscloud",
    "rollbar/rollbar",
    "rootlyhq/rootly",
    "russellcardullo/pingdom",
    "salrashid123/http-full",
    "scaleway/scaleway",
    "schwarzit/stackit",
    "scottwinkler/shell",
    "selectel/selectel",
    "siderolabs/talos",
    "slok/dataprocessor",
    "smutel/netbox",
    "snowflakedb/snowflake",
    "spacelift-io/spacelift",
    "spectrocloud/spectrocloud",
    "splunk-terraform/signalfx",
    "splunk/splunk",
    "splunk/synthetics",
    "spotinst/spotinst",
    "spring-media/pingdom",
    "stackitcloud/stackit",
    "statuscakedev/statuscake",
    "stileeducation/stile",
    "strongdm/sdm",
    "sullivtr/graphql",
    "sumologic/sumologic",
    "sysdiglabs/sysdig",
    "tailscale/tailscale",
    "telmate/proxmox",
    "temporalio/temporalcloud",
    "tencentcloudstack/tencentcloud",
    "tenstad/remote",
    "terraform-aws-modules/http",
    "terraform-lxd/lxd",
    "terraform-provider-concourse/concourse",
    "terraform-provider-openstack/openstack",
    "terraform-routeros/routeros",
    "timescale/timescale",
    "tiwood/azresourcegraph",
    "tlkamp/validation",
    "twilio/twilio",
    "twingate/twingate",
    "ucloud/ucloud",
    "unleash/unleash",
    "upcloudltd/upcloud",
    "vancluever/acme",
    "venafi/venafi",
    "vercel/vercel",
    "vexxhost/uptimerobot",
    "vk-cs/vkcs",
    "vmware/avi",
    "vmware/nsxt",
    "vmware/vcd",
    "vmware/vra",
    "vmware/vsphere",
    "vmware/wavefront",
    "vultr/vultr",
    "winebarrel/mysql",
    "yandex-cloud/yandex",
    "zitadel/zitadel",
    "zscaler/zpa",
];

/// `Some(1.0)` when `name` is one edit from a popular package's name in its
/// ecosystem without being one, `Some(0.0)` when it was checked and is not,
/// `None` when the ecosystem has no list.
pub(super) fn name_lookalike(ecosystem: &str, name: &str) -> Option<f64> {
    if !ecosystem.eq_ignore_ascii_case("terraform") {
        return None;
    }
    let name = name.trim().to_ascii_lowercase();
    if TERRAFORM_POPULAR.binary_search(&name.as_str()).is_ok() {
        return Some(0.0);
    }
    let (ns, typ) = name.split_once('/')?;
    let hit = TERRAFORM_POPULAR.iter().any(|p| {
        p.split_once('/')
            .is_some_and(|(pns, ptyp)| ptyp == typ && one_edit(ns, pns))
    });
    Some(f64::from(u8::from(hit)))
}

/// True when `a` and `b` differ by exactly one substitution, insertion,
/// deletion, or swap of adjacent characters. The swap matters: `hashicrop` is
/// the typo a hand makes, and plain Levenshtein counts it as two.
fn one_edit(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a == b || a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    // Past the common prefix, the rest must line up after one edit at i.
    let i = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    match a.len().cmp(&b.len()) {
        Ordering::Equal => {
            a[i + 1..] == b[i + 1..]
                || (i + 1 < a.len()
                    && a[i] == b[i + 1]
                    && a[i + 1] == b[i]
                    && a[i + 2..] == b[i + 2..])
        }
        Ordering::Greater => a[i + 1..] == b[i..],
        Ordering::Less => a[i..] == b[i + 1..],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popular_list_is_sorted_for_binary_search() {
        assert!(TERRAFORM_POPULAR.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn flags_a_namespace_one_edit_from_a_popular_provider() {
        assert_eq!(name_lookalike("terraform", "kreuzwenker/docker"), Some(1.0));
        assert_eq!(name_lookalike("terraform", "Kreuzwenker/Docker"), Some(1.0));
        // Swap, insertion, deletion.
        assert_eq!(name_lookalike("terraform", "hashicrop/aws"), Some(1.0));
        assert_eq!(name_lookalike("terraform", "hashicorpp/aws"), Some(1.0));
        assert_eq!(name_lookalike("terraform", "hashcorp/aws"), Some(1.0));
    }

    #[test]
    fn leaves_the_real_provider_forks_and_other_ecosystems_alone() {
        assert_eq!(name_lookalike("terraform", "kreuzwerker/docker"), Some(0.0));
        // Two edits: a legitimate fork, not a squat.
        assert_eq!(name_lookalike("terraform", "cnrancher/rancher2"), Some(0.0));
        // A popular type under an unrelated namespace is ordinary.
        assert_eq!(
            name_lookalike("terraform", "gocommunity-io/docker"),
            Some(0.0)
        );
        // A lookalike namespace with a different type is not this shape.
        assert_eq!(name_lookalike("terraform", "hashicrop/dockerd"), Some(0.0));
        assert_eq!(name_lookalike("terraform", "docker"), None);
        assert_eq!(name_lookalike("npm", "kreuzwenker/docker"), None);
    }

    #[test]
    fn one_edit_is_exactly_one() {
        for (a, b) in [
            ("ab", "ba"),
            ("abc", "abd"),
            ("abc", "ab"),
            ("ab", "abc"),
            ("a", ""),
        ] {
            assert!(one_edit(a, b), "{a} vs {b}");
        }
        for (a, b) in [
            ("abc", "abc"),
            ("abc", "cba"),
            ("abcd", "badc"),
            ("abc", "a"),
            ("", ""),
        ] {
            assert!(!one_edit(a, b), "{a} vs {b}");
        }
    }
}
