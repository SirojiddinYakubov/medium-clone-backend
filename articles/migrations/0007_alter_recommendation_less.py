# Generated by Django 5.0.4 on 2024-07-09 04:32

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0006_alter_article_views_count_alter_clap_count"),
    ]

    operations = [
        migrations.AlterField(
            model_name="recommendation",
            name="less",
            field=models.ForeignKey(
                blank=True,
                limit_choices_to={"is_active": True},
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="less_recommended",
                to="articles.topic",
            ),
        ),
    ]