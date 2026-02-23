# S3 Bucket Analiz Aracı

## Hızlı Başlangıç – Çalıştırma Komutları

```bash
# 1. Dizine geç ve sanal ortamı etkinleştir
cd /path/to/aws-s3-BucketAnalyzer
source .venv/bin/activate

# 2. İlk kurulumda (sadece bir kez)
pip install -r requirements.txt

# 3. Tüm bucket'ları analiz et ve CSV raporu oluştur
# Rapor adı: AWS_PROFILE_YYYY-MM-DD.csv (örn: my-profile_2026-02-23.csv)
AWS_PROFILE=your-aws-profile python s3_bucket_analyzer.py --all --csv
```

**Tek satırda:**
```bash
cd /path/to/aws-s3-BucketAnalyzer && source .venv/bin/activate && AWS_PROFILE=your-aws-profile python s3_bucket_analyzer.py --all --csv
```

---

## Özellikler

- **Versioning**: Bucket versioning durumu (Enabled/Suspended/Disabled)
- **Şifreleme**: Server-side encryption (AES256, KMS veya yok)
- **Public Access Block**: Public erişim engelleme ayarları
- **Logging**: S3 access logging durumu
- **CloudWatch Metrikleri**: NumberOfObjects ve BucketSizeBytes (son değer)
- **Obje Analizi** (opsiyonel): Obje sayısı ve toplam depolama boyutu
- **Güvenlik Önerileri**: Tespit edilen sorunlar ve iyileştirme önerileri

## Kurulum

```bash
cd /path/to/aws-s3-BucketAnalyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## AWS Kimlik Bilgileri

AWS CLI profili veya ortam değişkenleri kullanılır:

```bash
# AWS CLI profili (önerilen)
export AWS_PROFILE=your-aws-profile

# veya ortam değişkenleri
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=eu-west-1
```

## Kullanım

### Tüm bucket'ları analiz et + CSV raporu

```bash
# Rapor: your-aws-profile_2026-02-23.csv
AWS_PROFILE=your-aws-profile python s3_bucket_analyzer.py --all --csv

# Özel dosya adı ile
python s3_bucket_analyzer.py --all --profile your-aws-profile --csv ozel-rapor.csv
```

### Tüm bucket'ları analiz et (ekran çıktısı)

```bash
python s3_bucket_analyzer.py --all --profile your-aws-profile
```

### Tek bucket analizi

```bash
python s3_bucket_analyzer.py --bucket my-bucket-name --profile your-aws-profile
```

### JSON raporu

```bash
python s3_bucket_analyzer.py --all --profile your-aws-profile --json rapor.json
```

### Obje sayısı ve boyut analizi (yavaş)

```bash
python s3_bucket_analyzer.py --all --objects --profile your-aws-profile
```

### Belirli bölge

```bash
python s3_bucket_analyzer.py --all --region eu-west-1 --profile your-aws-profile
```

## Komut Satırı Parametreleri

| Parametre | Kısa | Açıklama |
|-----------|------|----------|
| `--all` | `-a` | Tüm bucket'ları analiz et |
| `--bucket` | `-b` | Tek bucket analizi |
| `--profile` | `-p` | AWS profil adı |
| `--region` | `-r` | AWS bölgesi |
| `--csv` | `-c` | CSV raporu. Dosya adı yoksa: AWS_PROFILE_YYYY-MM-DD.csv |
| `--json` | `-j` | JSON dosyasına kaydet |
| `--objects` | `-o` | Obje sayısı/boyut analizi (yavaş) |

## Rapor Dosya Adlandırma

`--csv` kullanıldığında dosya adı belirtilmezse rapor şu formatta oluşturulur:

```
{AWS_PROFILE}_{YYYY-MM-DD}.csv
```

Örnek: `your-aws-profile_2026-02-23.csv`

## CSV Rapor Sütunları

| Sütun | Açıklama |
|-------|----------|
| Bucket Name | Bucket adı |
| Region | AWS bölgesi |
| Creation Date | Oluşturulma tarihi |
| Versioning | Enabled / Suspended / Disabled |
| Encryption | AES256, aws:kms veya None |
| BlockPublicAcls | Public ACL engelleme |
| IgnorePublicAcls | Public ACL yok sayma |
| BlockPublicPolicy | Public policy engelleme |
| RestrictPublicBuckets | Public bucket kısıtlama |
| Bucket Policy | Var / Yok |
| Bucket Policy (JSON) | Policy içeriği (özet) |
| Logging Enabled | S3 access logging durumu |
| Logging Target | Log hedef bucket |
| Metric: NumberOfObjects | CloudWatch obje sayısı |
| Metric: BucketSizeBytes | CloudWatch depolama boyutu |

## Kontrol Edilen Güvenlik Kriterleri

| Kriter | Açıklama |
|--------|----------|
| Versioning | Veri kurtarma için versioning aktif olmalı |
| Encryption | Server-side şifreleme (AES256 veya KMS) |
| Public Access Block | Tüm 4 ayar aktif olmalı |
| Logging | S3 access logları audit için önerilir |

## Örnek Rapor Çıktısı

Aşağıda `your-aws-profile_2026-02-23.csv` raporunun tablo görünümü yer almaktadır (örnek çıktı):

<div style="overflow-x: auto; max-width: 100%;">

<table>
<thead>
<tr><th>Bucket Name</th><th>Region</th><th>Versioning</th><th>Encryption</th><th>Public Block</th><th>Bucket Policy</th><th>Logging</th><th>Objeler</th><th>Boyut</th></tr>
</thead>
<tbody>
<tr><td>aws-ia-trusting-elk-management-web-app-cloudtrail-logs-7d7d3507</td><td>us-west-2</td><td>Suspended</td><td>aws:kms</td><td>✓</td><td>Var</td><td>Hayır</td><td>30.706</td><td>229.7 MB</td></tr>
<tr><td>cdn.example.com</td><td>us-west-2</td><td>Enabled</td><td>AES256</td><td>✓</td><td>Var</td><td>Hayır</td><td>75</td><td>8.9 MB</td></tr>
<tr><td>org-finops</td><td>us-west-2</td><td>Enabled</td><td>AES256</td><td>✓</td><td>Var</td><td>Hayır</td><td>1.051</td><td>935.5 MB</td></tr>
<tr><td>org-management-alb-access-logs</td><td>us-west-2</td><td>Disabled</td><td>AES256</td><td>✓</td><td>Var</td><td>Hayır</td><td>8.725</td><td>12.9 MB</td></tr>
<tr><td>org-management-aws-config</td><td>us-west-2</td><td>Enabled</td><td>AES256</td><td>✓</td><td>Yok</td><td>Hayır</td><td>3.147</td><td>37.6 MB</td></tr>
<tr><td>org-terraform-states</td><td>us-west-2</td><td>Enabled</td><td>AES256</td><td>✓</td><td>Yok</td><td>Hayır</td><td>2.952</td><td>96.9 MB</td></tr>
<tr><td>logs.example.com</td><td>us-west-2</td><td>Disabled</td><td>AES256</td><td>✓</td><td>Yok</td><td>Hayır</td><td>56</td><td>38.6 KB</td></tr>
<tr><td>us-west-2-management-cloudtrail</td><td>us-west-2</td><td>Suspended</td><td>AES256</td><td>✓</td><td>Var</td><td>Hayır</td><td>158.360</td><td>1.0 GB</td></tr>
</tbody>
</table>

</div>

*Public Block: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets (tümü True)*

