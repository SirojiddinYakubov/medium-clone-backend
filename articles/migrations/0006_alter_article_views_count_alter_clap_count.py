# Generated by Django 5.0.4 on 2024-07-08 12:31

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0005_alter_article_views_count_alter_clap_count"),
    ]

    operations = [
        migrations.AlterField(
            model_name="article",
            name="views_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="clap",
            name="count",
            field=models.PositiveIntegerField(
                default=0, validators=[django.core.validators.MaxValueValidator(50)]
            ),
        ),
    ]