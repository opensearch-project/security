[![CI](https://github.com/opensearch-project/security/workflows/CI/badge.svg?branch=main)](https://github.com/opensearch-project/security/actions) [![](https://img.shields.io/github/issues/opensearch-project/security/untriaged?labelColor=red)](https://github.com/opensearch-project/security/issues?q=is%3Aissue+is%3Aopen+label%3A"untriaged") [![](https://img.shields.io/github/issues/opensearch-project/security/security%20vulnerability?labelColor=red)](https://github.com/opensearch-project/security/issues?q=is%3Aissue+is%3Aopen+label%3A"security%20vulnerability") [![](https://img.shields.io/github/issues/opensearch-project/security)](https://github.com/opensearch-project/security/issues) [![](https://img.shields.io/github/issues-pr/opensearch-project/security)](https://github.com/opensearch-project/security/pulls) [![](https://img.shiel) ds.io/codecov/c/gh/opensearch-project/security)](https://app.codecov.io/gh/opensearch-project/security) [![](https://img.shields.io/github/issues/opensearch-project/security/v2.18.0)](https://github.com/opensearch-project/security/issues?q=is%3Aissue+is%3Aopen+label%3A "v2.18.0") [![](https://img.shields.io/github/issues/opensearch-project/security/v3.0.0)](https://github.com/opensearch-project/security/issues?q=is%3Aissue+is%3Aopen+label%3A"v3.0.0")
[![Slack](https://img.shields.io/badge/Slack-4A154B?&logo=slack&logoColor=white)](https://opensearch.slack.com/archives/C051Y637FKK)

## Duyuru: Slack çalışma alanı yayında! Lütfen [sohbete](https://opensearch.slack.com/archives/C051Y637FKK) katılın.

<img src="https://opensearch.org/assets/img/opensearch-logo-themed.svg" height="64px">

# OpenSearch Güvenlik Eklentisi

OpenSearch Güvenliği, şifreleme, kimlik doğrulama ve yetkilendirme sunan bir OpenSearch eklentisidir. OpenSearch Security-Advanced Modülleri ile birleştirildiğinde, Active Directory, LDAP, Kerberos, JSON web belirteçleri, SAML, OpenID ve daha fazlası aracılığıyla kimlik doğrulamayı destekler. Dizinlere, belgelere ve alanlara ince ayrıntılı rol tabanlı erişim denetimi içerir. Ayrıca OpenSearch Panolarında çoklu kiracı desteği sağlar.

- [OpenSearch Güvenlik Eklentisi](#opensearch-security-plugin)
- [Özellikler](#özellikler)
- [Şifreleme](#şifreleme)
- [Kimlik Doğrulama](#kimlik doğrulama)
- [Erişim denetimi](#erişim denetimi)
- [Denetim/Uyumluluk kaydı](#auditcompliance-logging)
- [OpenSearch Panoları çoklu kiracı](#opensearch-dashboards-çoklu kiracı)
- [Kurulum](#kurulum)
- [Test ve Derleme](#test-and-build)
- [Sıcak yeniden yüklemeyi yapılandır](#config-hot-reloading)
- [Yeni API'leri yerleştirme](#onboarding-new-apis)
- [Sistem Dizin Koruması](#system-index-protection)
- [Katkıda Bulunma](#contributing)
- [Alma Yardım](#getting-help)
- [Davranış Kuralları](#davranış-kuralları)
- [Güvenlik](#güvenlik)
- [Lisans](#lisans)
- [Telif Hakkı](#telif hakkı)

## Özellikler

### Şifreleme
* Transit sırasında tam veri şifrelemesi
* Düğümler arası şifreleme
* Sertifika iptal listeleri
* Sıcak Sertifika yenileme

### Kimlik doğrulama
* Dahili kullanıcı veritabanı
* HTTP temel kimlik doğrulaması
* PKI kimlik doğrulaması
* Proxy kimlik doğrulaması
* Kullanıcı Kimliğine Bürünme
* Active Directory / LDAP
* Kerberos / SPNEGO
* JSON web belirteci (JWT)
* OpenID Connect (OIDC)
* SAML

### Erişim denetimi
* Rol tabanlı küme düzeyinde erişim denetimi
* Rol tabanlı dizin düzeyinde erişim denetimi
* Kullanıcı, rol ve izin yönetimi
* Belge düzeyinde güvenlik
* Alan düzeyinde güvenlik
* REST yönetim API'si

### Denetim/Uyumluluk günlük kaydı
* Denetim günlüğü
* GDPR, HIPAA, PCI, SOX ve ISO uyumluluğu için uyumluluk günlüğü

### OpenSearch Panoları çoklu kiracı
* Gerçek OpenSearch Panoları çoklu kiracı

## Kurulum

OpenSearch Güvenlik Eklentisi varsayılan olarak OpenSearch dağıtımının bir parçası olarak birlikte gelir. OpenSearch Güvenlik Eklentisini yükleme ve yapılandırma hakkında ayrıntılı bilgi için lütfen [kurulum kılavuzuna](https://opensearch.org/docs/latest/opensearch/install/index/) ve [teknik belgelere](https://opensearch.org/docs/latest/security-plugin/index/) bakın.

Ayrıca, başlangıçta eklentiye sahip olmayan bir OpenSearch sunucusu için eklentinin kurulumunu adım adım açıklayan [geliştirici kılavuzuna](https://github.com/opensearch-project/security/blob/main/DEVELOPER_GUIDE.md) da bakabilirsiniz.

## Test ve Oluşturma

Tüm testleri çalıştırın:
```bash
./gradlew clean test
```

Testleri yerel kümeye karşı çalıştırın:
```bash
./gradlew integTestRemote -Dtests.rest.cluster=localhost:9200 -Dtests.cluster=localhost:9200 -Dtests.clustername=docker-cluster -Dsecurity=true -Dhttps=true -Duser=admin -Dpassword=admin -Dcommon_utils.version="2.2.0.0"
```
VEYA
```bash
./scripts/integtest.sh
```
Not: Uzak bir kümeye karşı çalıştırmak için cluster-name ve `localhost:9200` öğelerini o kümenin IPAddress:Port'uyla değiştirin.

Yapıtları derle (zip, deb, rpm):
```bash
./gradlew clean assembly
artifact_zip=`ls $(pwd)/build/distributions/opensearch-security-*.zip | grep -v admin-standalone`
./gradlew buildDeb buildRpm -ParchivePath=$artifact_zip
```

Bu şunu üretir:

```
build/releases/opensearch-security-<VERSION>.zip
build/distributions/opensearch-security-<VERSION>.deb
build/distributions/opensearch-security-<VERSION>.rpm
```

## Yapılandırma sıcak yeniden yükleme

Güvenlik Eklentisi yapılandırması OpenSearch'ün kendisinde özel bir dizinde saklanır. Yapılandırmadaki değişiklikler komut satırı aracı aracılığıyla bu dizine gönderilir. Bu, tüm düğümlerde yapılandırmanın otomatik olarak yeniden yüklenmesini tetikler. Bunun `opensearch.yml` aracılığıyla yapılandırmaya göre birkaç avantajı vardır:

* Yapılandırma merkezi bir yerde saklanır
* Düğümlerde yapılandırma dosyası gerekmez
* Yapılandırma değişiklikleri yeniden başlatma gerektirmez
* Yapılandırma değişiklikleri hemen etkili olur

## Yeni API'leri dahil etme

Yeni API'ler geliştirirken düğümler arasında farklı görevler gerçekleştirmek için yeni taşıma eylemleri oluşturmak yaygın bir uygulamadır. Bu eylemleri güvenlikle entegre etmek ve entegre etmek isteyen yeni veya mevcut eklentiler için aşağıdaki adımları izlemeleri gerekir:
1. Eyleminize bir ad verin ([örnek](https://github.com/opensearch-project/anomaly-detection/blob/main/src/main/java/org/opensearch/ad/transport/SearchADTasksAction.java#L35)) ve eklentinizde kaydedin ([örnek](https://github.com/opensearch-project/anomaly-detection/blob/main/src/main/java/org/opensearch/ad/AnomalyDetectorPlugin.java#L935)). En iyi uygulama, eylem adlarını farklı eklentiler arasında düzenli tutmak için hiyerarşik bir desen izleyen mevcut adlandırma kurallarını takip etmektir.
2. Eylemi [OpenSearch Güvenlik eklentisine](https://github.com/opensearch-project/security) kaydedin. Her yeni eylem eklentide yeni bir izin olarak kaydedilir. Genellikle eklentiler eklentileri için farklı roller tanımlar (örneğin salt okunur erişim, yazma erişimi). Her rol bir izin kümesi içerir. [Anomaly Detection eklentisi](https://github.com/opensearch-project/anomaly-detection) için `anomaly_read_access` rolüne yeni bir izin eklemenin bir örneği [bu PR'de](https://github.com/opensearch-project/security/pull/997/files) bulunabilir.
3. Eylemi [OpenSearch Dashboards Security eklentisinde](https://github.com/opensearch-project/security-dashboards-plugin) kaydedin. Bu eklenti olası izinlerin tam listesini korur, böylece kullanıcılar yeni roller oluştururken veya Dashboard'lar aracılığıyla izinleri ararken bunların hepsini görebilir. Farklı izinler eklemenin bir örneği [bu PR'de](https://github.com/opensearch-project/security-dashboards-plugin/pull/689/files) bulunabilir.

ARCHITECTURE.md'deki [plugin-authorization-flows](ARCHITECTURE.md#plugin-authorization-flows)'a bakın.

### Sistem Dizin Koruması

Güvenlik Eklentisi, eklentiler tarafından kullanılan sistem dizinlerine koruma sağlar. Sistem dizin adları, `plugins.security.system_indices.indices` ayarı altında `opensearch.yml`'de açıkça kaydedilmelidir. Demo yapılandırmasından sistem dizin korumasının örnek kurulumu için aşağıya bakın:

```
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]
```

Demo yapılandırması, demo yapılandırmasına yeni bir sistem dizini eklemek için aşağıdaki dosyalarda değiştirilebilir:

- https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/tools/democonfig/SecuritySettingsConfigurer.java

## Katkıda Bulunma

Bkz. [geliştirici kılavuzu](DEVELOPER_GUIDE.md) ve [bu projeye nasıl katkıda bulunulur](CONTRIBUTING.md).

## Yardım Alma

Bir hata bulursanız veya bir özellik isteğiniz varsa, lütfen bu depoda bir sorun açmaktan çekinmeyin.

Daha fazla bilgi için [proje web sitesi](https://opensearch.org/) ve [belgeler](https://opensearch.org/docs/latest) bölümüne bakın. Yardıma ihtiyacınız varsa ve bir sorunu nerede açacağınızdan emin değilseniz [forumları](https://discuss.opendistrocommunity.dev/) deneyin.

## Davranış Kuralları

Bu proje [Amazon Açık Kaynak Davranış Kuralları](CODE_OF_CONDUCT.md)'nı benimsemiştir. Daha fazla bilgi için [Davranış Kuralları SSS](https://aws.github.io/code-of-conduct-faq)'na bakın veya ek sorularınız veya yorumlarınız için [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) ile iletişime geçin.

## Güvenlik

Bu projede olası bir güvenlik sorunu keşfederseniz, lütfen OpenSearch Security'yi doğrudan security@opensearch.org adresine e-posta göndererek bilgilendirmenizi rica ederiz. Lütfen genel bir GitHub sorunu **oluşturmayın**.

## Lisans

Bu kod Apache 2.0 Lisansı altında lisanslanmıştır.

## Telif Hakkı

Telif Hakkı OpenSearch Katkıda Bulunanlara aittir. Ayrıntılar için [NOTICE](NOTICE.txt) dosyasına bakın.
