import discord
import sys
from discord import app_commands

from config import DISCORD_TOKEN
from security.support import handle_support
from bot.vpn_commands import setup_vpn_commands


class GuardianProBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await self.tree.sync()
        print("[Guardian Pro Bot] Commands synced.")

    async def on_ready(self):
        print(f"[Guardian Pro Bot] Online as {self.user}")


bot = GuardianProBot()
setup_vpn_commands(bot.tree)


@bot.tree.command(
    name="ping",
    description="Check that Guardian Pro Bot is online."
)
async def ping(interaction: discord.Interaction):
    await interaction.response.send_message(
        "Guardian Pro Bot شغال ✅",
        ephemeral=True,
    )


@bot.tree.command(
    name="protect",
    description="Run a security audit on this Discord server."
)
async def protect(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild

    if guild is None:
        await interaction.followup.send(
            "الأمر ده لازم يتستخدم داخل السيرفر.",
            ephemeral=True,
        )
        return

    me = guild.me

    if me is None:
        await interaction.followup.send(
            "مش قادر أحدد صلاحيات البوت حاليًا.",
            ephemeral=True,
        )
        return

    perm = me.guild_permissions

    # -------------------------
    # Permission audit
    # -------------------------
    permission_checks = {
        "Administrator": perm.administrator,
        "Manage Server": perm.manage_guild,
        "Manage Roles": perm.manage_roles,
        "Manage Channels": perm.manage_channels,
        "Manage Webhooks": perm.manage_webhooks,
        "Kick Members": perm.kick_members,
        "Ban Members": perm.ban_members,
        "Moderate Members": perm.moderate_members,
        "View Audit Log": perm.view_audit_log,
    }

    permission_lines = []

    for name, enabled in permission_checks.items():
        icon = "✅" if enabled else "⚠️"
        permission_lines.append(f"{icon} {name}")

    # -------------------------
    # Role audit
    # -------------------------
    dangerous_roles = []

    for role in guild.roles:
        if role.is_default():
            continue

        dangerous = (
            role.permissions.administrator
            or role.permissions.manage_guild
            or role.permissions.manage_roles
            or role.permissions.manage_channels
            or role.permissions.ban_members
            or role.permissions.kick_members
            or role.permissions.manage_webhooks
        )

        if dangerous:
            dangerous_roles.append(role)

    # -------------------------
    # Bot audit
    # -------------------------
    bots = [
        member
        for member in guild.members
        if member.bot
    ]

    # -------------------------
    # Webhook audit
    # -------------------------
    webhook_count = 0
    webhook_error = False

    if perm.manage_webhooks:
        try:
            for channel in guild.text_channels:
                try:
                    hooks = await channel.webhooks()
                    webhook_count += len(hooks)
                except discord.Forbidden:
                    webhook_error = True
                except discord.HTTPException:
                    webhook_error = True
        except discord.Forbidden:
            webhook_error = True
        except discord.HTTPException:
            webhook_error = True
    else:
        webhook_error = True

    # -------------------------
    # Channel audit
    # -------------------------
    channels_without_view = []

    for channel in guild.text_channels:
        permissions = channel.permissions_for(me)

        if not permissions.view_channel:
            channels_without_view.append(channel)

    # -------------------------
    # AutoMod audit
    # -------------------------
    automod_status = "غير متاح للفحص"

    try:
        if perm.manage_guild:
            rules = await guild.fetch_automod_rules()
            automod_status = f"تم العثور على {len(rules)} قاعدة AutoMod"
        else:
            automod_status = "البوت يحتاج Manage Server للفحص"
    except (discord.Forbidden, discord.HTTPException):
        automod_status = "تعذر الوصول إلى AutoMod"

    # -------------------------
    # Security score
    # -------------------------
    score = 100

    if not perm.view_audit_log:
        score -= 10

    if not perm.manage_webhooks:
        score -= 10

    if not perm.manage_roles:
        score -= 10

    if not perm.manage_channels:
        score -= 10

    if webhook_error:
        score -= 5

    score = max(0, score)

    # -------------------------
    # Report
    # -------------------------
    lines = [
        "🛡️ **Guardian Pro Bot — Security Report**",
        f"**السيرفر:** {guild.name}",
        f"**الأعضاء:** {guild.member_count or 0}",
        f"**Security Score:** `{score}/100`",
        "",
        "### 🔐 صلاحيات Guardian",
        *permission_lines,
        "",
        "### 👑 الأدوار الحساسة",
        f"عدد الأدوار ذات الصلاحيات الحساسة: `{len(dangerous_roles)}`",
        "",
        "### 🤖 البوتات",
        f"عدد البوتات: `{len(bots)}`",
        "",
        "### 🔗 Webhooks",
        f"عدد الـWebhooks المكتشفة: `{webhook_count}`",
        (
            "⚠️ بعض الـWebhooks لم يمكن فحصها."
            if webhook_error
            else "✅ فحص الـWebhooks مكتمل."
        ),
        "",
        "### 📢 القنوات",
        f"قنوات لا يستطيع Guardian رؤيتها: `{len(channels_without_view)}`",
        "",
        "### 🛡️ AutoMod",
        automod_status,
        "",
        "⚠️ **وضع الفحص فقط:**",
        "لم يتم تعديل أي إعداد أو حذف أي شيء.",
    ]

    report = "\n".join(lines)

    # Discord message limit safety.
    if len(report) > 1900:
        report = report[:1890] + "\n..."

    await interaction.followup.send(
        report,
        ephemeral=True,
    )


@bot.tree.command(
    name="دعم_فني",
    description="Technical support: diagnose and fix confirmed bot errors."
)
@app_commands.describe(
    الخطأ="اكتب الخطأ أو المشكلة التي ظهرت للبوت."
)
async def دعم_فني(interaction: discord.Interaction, الخطأ: str):
    # الأمر حساس لأنه يستطيع تعديل ملفات المشروع.
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message(
            "الأمر ده متاح للإدارة فقط.",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True)

    try:
        result = await handle_support(الخطأ)

        if isinstance(result, tuple) and result[1] is True:
            await interaction.followup.send(
                result[0],
                ephemeral=True,
            )

        else:
            await interaction.followup.send(
                result,
                ephemeral=True,
            )

    except Exception as exc:
        await interaction.followup.send(
            f"تعذر تنفيذ الدعم الفني: {exc}",
            ephemeral=True,
        )


if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN is not configured")


bot.run(DISCORD_TOKEN)
