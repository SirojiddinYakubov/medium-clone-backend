# Generated by Django 5.0.4 on 2024-07-03 06:53

import django.contrib.auth.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0005_customuser_customuser_first_name_hash_idx_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="email_en",
            field=models.EmailField(
                blank=True, max_length=254, null=True, verbose_name="email address"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="email_ru",
            field=models.EmailField(
                blank=True, max_length=254, null=True, verbose_name="email address"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="email_uz",
            field=models.EmailField(
                blank=True, max_length=254, null=True, verbose_name="email address"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="first_name_en",
            field=models.CharField(
                blank=True, max_length=150, null=True, verbose_name="first name"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="first_name_ru",
            field=models.CharField(
                blank=True, max_length=150, null=True, verbose_name="first name"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="first_name_uz",
            field=models.CharField(
                blank=True, max_length=150, null=True, verbose_name="first name"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="last_name_en",
            field=models.CharField(
                blank=True, max_length=150, null=True, verbose_name="last name"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="last_name_ru",
            field=models.CharField(
                blank=True, max_length=150, null=True, verbose_name="last name"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="last_name_uz",
            field=models.CharField(
                blank=True, max_length=150, null=True, verbose_name="last name"
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="middle_name_en",
            field=models.CharField(blank=True, max_length=30, null=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="middle_name_ru",
            field=models.CharField(blank=True, max_length=30, null=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="middle_name_uz",
            field=models.CharField(blank=True, max_length=30, null=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="username_en",
            field=models.CharField(
                error_messages={"unique": "A user with that username already exists."},
                help_text="Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.",
                max_length=150,
                null=True,
                unique=True,
                validators=[django.contrib.auth.validators.UnicodeUsernameValidator()],
                verbose_name="username",
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="username_ru",
            field=models.CharField(
                error_messages={"unique": "A user with that username already exists."},
                help_text="Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.",
                max_length=150,
                null=True,
                unique=True,
                validators=[django.contrib.auth.validators.UnicodeUsernameValidator()],
                verbose_name="username",
            ),
        ),
        migrations.AddField(
            model_name="customuser",
            name="username_uz",
            field=models.CharField(
                error_messages={"unique": "A user with that username already exists."},
                help_text="Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.",
                max_length=150,
                null=True,
                unique=True,
                validators=[django.contrib.auth.validators.UnicodeUsernameValidator()],
                verbose_name="username",
            ),
        ),
    ]
