# Generated by Django 4.1.5 on 2023-01-04 11:09

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BankingInformation',
            fields=[
                ('bank_info_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('bank_name', models.CharField(max_length=30)),
                ('account_name', models.CharField(max_length=30)),
                ('account_number', models.IntegerField()),
                ('ifsc_code', models.CharField(max_length=15)),
                ('modified_by', models.CharField(blank=True, max_length=20, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('last_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
