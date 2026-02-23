#!/usr/bin/env python3
"""
AWS S3 Bucket Analiz Aracı
--------------------------
S3 bucket'larının güvenlik, şifreleme, versioning ve yapılandırma durumunu analiz eder.
LingaDR-Lab için hazırlanmıştır.
"""

import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from typing import Optional, List
from dataclasses import dataclass, asdict


@dataclass
class BucketAnalysis:
    """S3 bucket analiz sonucu"""
    bucket_name: str
    region: str
    creation_date: str
    versioning: str  # Enabled, Suspended, Disabled
    encryption: str  # AES256, aws:kms, None
    public_access_block: dict
    bucket_policy: Optional[str]  # JSON policy veya None
    logging_enabled: bool
    logging_target: Optional[str]
    object_count: Optional[int]
    total_size_bytes: Optional[int]
    metric_number_of_objects: Optional[float]
    metric_bucket_size_bytes: Optional[float]
    issues: list
    recommendations: list


def get_s3_client(region: Optional[str] = None, profile: Optional[str] = None):
    """S3 client oluştur"""
    session_kw = {}
    if profile:
        session_kw['profile_name'] = profile
    session = boto3.Session(**session_kw) if session_kw else boto3.Session()
    return session.client('s3', region_name=region)


def get_cloudwatch_client(region: Optional[str] = None, profile: Optional[str] = None):
    """CloudWatch client oluştur"""
    session_kw = {}
    if profile:
        session_kw['profile_name'] = profile
    session = boto3.Session(**session_kw) if session_kw else boto3.Session()
    return session.client('cloudwatch', region_name=region)


def get_s3_metrics(bucket_name: str, bucket_region: str, profile: Optional[str] = None) -> tuple:
    """
    S3 bucket CloudWatch metriklerinin son değerini alır.
    Returns: (NumberOfObjects, BucketSizeBytes)
    """
    cw = get_cloudwatch_client(bucket_region or 'us-east-1', profile)
    end = datetime.now(timezone.utc)
    start = datetime(end.year, end.month, max(1, end.day - 2), 0, 0, 0)  # Son 2 gün
    
    num_objects = None
    bucket_size = None
    
    try:
        # NumberOfObjects - AllStorageTypes
        resp = cw.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='NumberOfObjects',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
            ],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=['Average']
        )
        if resp.get('Datapoints'):
            latest = max(resp['Datapoints'], key=lambda x: x['Timestamp'])
            num_objects = latest.get('Average')
    except Exception:
        pass
    
    try:
        # BucketSizeBytes - StandardStorage (ana depolama)
        resp = cw.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=['Average']
        )
        if resp.get('Datapoints'):
            latest = max(resp['Datapoints'], key=lambda x: x['Timestamp'])
            bucket_size = latest.get('Average')
    except Exception:
        pass
    
    return (num_objects, bucket_size)


def analyze_bucket(bucket_name: str, region: Optional[str] = None, include_objects: bool = False,
                  creation_date: Optional[str] = None, profile: Optional[str] = None,
                  include_metrics: bool = True) -> BucketAnalysis:
    """
    Tek bir S3 bucket'ı analiz eder.
    
    Args:
        bucket_name: Bucket adı
        region: AWS bölgesi (opsiyonel)
        include_objects: Obje sayısı ve boyut analizi yapılsın mı (yavaş olabilir)
        profile: AWS profil adı
        include_metrics: CloudWatch metrikleri alınsın mı
    """
    s3 = get_s3_client(region, profile)
    issues = []
    recommendations = []
    
    # Bucket location
    try:
        location = s3.get_bucket_location(Bucket=bucket_name)
        bucket_region = location.get('LocationConstraint') or 'us-east-1'
    except Exception as e:
        bucket_region = region or 'unknown'
        issues.append(f"Bucket location alınamadı: {str(e)}")
    
    # Creation date (list_buckets'tan geçirilebilir)
    if not creation_date:
        try:
            buckets = s3.list_buckets()['Buckets']
            for b in buckets:
                if b['Name'] == bucket_name:
                    creation_date = b['CreationDate'].strftime('%Y-%m-%d %H:%M')
                    break
            else:
                creation_date = "N/A"
        except Exception:
            creation_date = "N/A"
    
    # Versioning
    versioning_status = "Disabled"
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        versioning_status = versioning.get('Status', 'Disabled') or 'Disabled'
        if versioning_status == 'Suspended':
            issues.append("Versioning askıya alınmış - veri kurtarma riski")
            recommendations.append("Versioning'i Enabled yapın")
    except Exception as e:
        issues.append(f"Versioning bilgisi alınamadı: {str(e)}")
    
    # Encryption
    encryption_status = "None"
    try:
        encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        if rules:
            encryption_status = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'Unknown')
        else:
            issues.append("Server-side şifreleme YOK - veri güvenliği riski")
            recommendations.append("S3 bucket için AES256 veya KMS şifrelemesi ekleyin")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            encryption_status = "None"
            issues.append("Server-side şifreleme YOK - veri güvenliği riski")
            recommendations.append("S3 bucket için AES256 veya KMS şifrelemesi ekleyin")
        else:
            issues.append(f"Şifreleme bilgisi alınamadı: {str(e)}")
    
    # Public Access Block
    public_access = {}
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab.get('PublicAccessBlockConfiguration', {})
        public_access = {
            'BlockPublicAcls': config.get('BlockPublicAcls', False),
            'IgnorePublicAcls': config.get('IgnorePublicAcls', False),
            'BlockPublicPolicy': config.get('BlockPublicPolicy', False),
            'RestrictPublicBuckets': config.get('RestrictPublicBuckets', False),
        }
        if not all(public_access.values()):
            issues.append("Public access block tam yapılandırılmamış - güvenlik riski")
            recommendations.append("Tüm public access block ayarlarını aktif edin")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            issues.append("Public access block YOK - bucket public erişime açık olabilir")
            recommendations.append("Public access block yapılandırması ekleyin")
            public_access = {'BlockPublicAcls': False, 'IgnorePublicAcls': False, 
                           'BlockPublicPolicy': False, 'RestrictPublicBuckets': False}
        else:
            issues.append(f"Public access block alınamadı: {str(e)}")
    
    # Bucket Policy
    bucket_policy = None
    try:
        policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
        bucket_policy = policy_resp.get('Policy', '')
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
            issues.append(f"Bucket policy alınamadı: {str(e)}")
    
    # Logging
    logging_enabled = False
    logging_target = None
    try:
        logging = s3.get_bucket_logging(Bucket=bucket_name)
        log_config = logging.get('LoggingEnabled', {})
        if log_config:
            logging_enabled = True
            logging_target = log_config.get('TargetBucket', '')
        else:
            recommendations.append("S3 access logging'i etkinleştirin (audit için)")
    except Exception as e:
        issues.append(f"Logging bilgisi alınamadı: {str(e)}")
    
    # Object count & size (opsiyonel - yavaş olabilir)
    object_count = None
    total_size = None
    if include_objects:
        try:
            paginator = s3.get_paginator('list_objects_v2')
            count = 0
            size = 0
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get('Contents', []):
                    count += 1
                    size += obj.get('Size', 0)
            object_count = count
            total_size = size
        except Exception as e:
            issues.append(f"Obje listesi alınamadı: {str(e)}")
    
    # CloudWatch metrikleri (son değer)
    metric_objects = None
    metric_size = None
    if include_metrics:
        try:
            metric_objects, metric_size = get_s3_metrics(bucket_name, bucket_region, profile)
        except Exception:
            pass
    
    return BucketAnalysis(
        bucket_name=bucket_name,
        region=bucket_region,
        creation_date=creation_date,
        versioning=versioning_status,
        encryption=encryption_status,
        public_access_block=public_access,
        bucket_policy=bucket_policy,
        logging_enabled=logging_enabled,
        logging_target=logging_target,
        object_count=object_count,
        total_size_bytes=total_size,
        metric_number_of_objects=metric_objects,
        metric_bucket_size_bytes=metric_size,
        issues=issues,
        recommendations=recommendations
    )


def analyze_all_buckets(region: Optional[str] = None, include_objects: bool = False,
                       profile: Optional[str] = None, include_metrics: bool = True) -> List[BucketAnalysis]:
    """Tüm S3 bucket'ları analiz eder"""
    s3 = get_s3_client(region, profile)
    buckets = s3.list_buckets()['Buckets']
    results = []
    
    for bucket in buckets:
        name = bucket['Name']
        created = bucket.get('CreationDate')
        creation_date = created.strftime('%Y-%m-%d %H:%M') if created else None
        print(f"Analiz ediliyor: {name}...")
        try:
            analysis = analyze_bucket(name, region, include_objects, creation_date, profile, include_metrics)
            results.append(analysis)
        except Exception as e:
            print(f"  Hata: {name} - {e}")
    
    return results


def format_size(size_bytes: Optional[int]) -> str:
    """Byte'ı okunabilir formata çevir"""
    if size_bytes is None:
        return "N/A"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def export_csv(analyses: List[BucketAnalysis], output_path: str):
    """Analiz sonuçlarını CSV dosyasına aktarır"""
    import csv
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow([
            'Bucket Name', 'Region', 'Creation Date',
            'Versioning', 'Encryption',
            'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets',
            'Bucket Policy', 'Bucket Policy (JSON)',
            'Logging Enabled', 'Logging Target',
            'Metric: NumberOfObjects', 'Metric: BucketSizeBytes (bytes)', 'Metric: BucketSizeBytes (readable)'
        ])
        for a in analyses:
            pab = a.public_access_block or {}
            metric_size_readable = format_size(int(a.metric_bucket_size_bytes)) if a.metric_bucket_size_bytes else 'N/A'
            policy_status = 'Var' if a.bucket_policy else 'Yok'
            policy_json = (a.bucket_policy or '').replace('\n', ' ').replace('\r', '')[:2000] or ''
            writer.writerow([
                a.bucket_name, a.region, a.creation_date,
                a.versioning, a.encryption,
                pab.get('BlockPublicAcls', ''),
                pab.get('IgnorePublicAcls', ''),
                pab.get('BlockPublicPolicy', ''),
                pab.get('RestrictPublicBuckets', ''),
                policy_status,
                policy_json,
                'Evet' if a.logging_enabled else 'Hayır',
                a.logging_target or '',
                a.metric_number_of_objects if a.metric_number_of_objects is not None else 'N/A',
                a.metric_bucket_size_bytes if a.metric_bucket_size_bytes is not None else 'N/A',
                metric_size_readable
            ])
    print(f"\n📄 CSV rapor kaydedildi: {output_path}")


def print_report(analyses: List[BucketAnalysis], output_json: Optional[str] = None):
    """Analiz raporunu yazdır"""
    print("\n" + "="*70)
    print("S3 BUCKET ANALİZ RAPORU")
    print(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("="*70)
    
    for a in analyses:
        print(f"\n📦 {a.bucket_name}")
        print(f"   Bölge: {a.region}")
        print(f"   Versioning: {a.versioning}")
        print(f"   Şifreleme: {a.encryption}")
        print(f"   Bucket Policy: {'Var' if a.bucket_policy else 'Yok'}")
        if a.bucket_policy:
            try:
                policy_preview = json.dumps(json.loads(a.bucket_policy), ensure_ascii=False)[:300]
                print(f"   Bucket Policy (özet): {policy_preview}...")
            except Exception:
                print(f"   Bucket Policy (özet): {(a.bucket_policy or '')[:200]}...")
        print(f"   Logging: {'Evet' if a.logging_enabled else 'Hayır'}")
        if a.object_count is not None:
            print(f"   Obje sayısı: {a.object_count:,}")
            print(f"   Toplam boyut: {format_size(a.total_size_bytes)}")
        if a.metric_number_of_objects is not None or a.metric_bucket_size_bytes is not None:
            print(f"   Metric (son): Objeler={a.metric_number_of_objects or 'N/A'}, Boyut={format_size(a.metric_bucket_size_bytes) if a.metric_bucket_size_bytes else 'N/A'}")
        if a.issues:
            print("   ⚠️  Sorunlar:")
            for i in a.issues:
                print(f"      - {i}")
        if a.recommendations:
            print("   💡 Öneriler:")
            for r in a.recommendations:
                print(f"      - {r}")
    
    if output_json:
        report = {
            'timestamp': datetime.now().isoformat(),
            'bucket_count': len(analyses),
            'buckets': [asdict(a) for a in analyses]
        }
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n📄 JSON rapor kaydedildi: {output_json}")


def main():
    import argparse
    import os
    parser = argparse.ArgumentParser(description='AWS S3 Bucket Analiz Aracı')
    parser.add_argument('--bucket', '-b', help='Tek bucket analizi')
    parser.add_argument('--region', '-r', help='AWS bölgesi (örn: eu-west-1)')
    parser.add_argument('--all', '-a', action='store_true', help='Tüm bucket\'ları analiz et')
    parser.add_argument('--objects', '-o', action='store_true', help='Obje sayısı ve boyut analizi (yavaş)')
    parser.add_argument('--profile', '-p', help='AWS profil adı (örn: lingarosdr-management)')
    parser.add_argument('--json', '-j', help='Sonucu JSON dosyasına kaydet')
    parser.add_argument('--csv', '-c', nargs='?', const=True, metavar='DOSYA',
                        help='CSV raporu oluştur. Dosya adı belirtilmezse: AWS_PROFILE_YYYY-MM-DD.csv')
    args = parser.parse_args()
    
    if args.bucket:
        analyses = [analyze_bucket(args.bucket, args.region, args.objects, profile=args.profile)]
    elif args.all:
        analyses = analyze_all_buckets(args.region, args.objects, args.profile)
    else:
        parser.print_help()
        print("\nÖrnek: python s3_bucket_analyzer.py --all --profile lingarosdr-management --csv")
        print("       python s3_bucket_analyzer.py --bucket my-bucket-name")
        return
    
    print_report(analyses, args.json)
    if args.csv:
        if args.csv is True:
            profile = args.profile or os.environ.get('AWS_PROFILE', 'default')
            date_str = datetime.now().strftime('%Y-%m-%d')
            csv_path = f"{profile}_{date_str}.csv"
        else:
            csv_path = args.csv
        export_csv(analyses, csv_path)


if __name__ == '__main__':
    main()
