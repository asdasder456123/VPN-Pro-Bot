import discord
from discord import app_commands

from vpn.manager import WireGuardManager


def setup_vpn_commands(tree: app_commands.CommandTree):
    manager = WireGuardManager()

    @tree.command(
        name="vpn",
        description="إنشاء إعداد WireGuard خاص بك"
    )
    async def vpn(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        try:
            config_path, public_key, address = manager.create_client(
                str(interaction.user.id)
            )

            await interaction.followup.send(
                content=(
                    "تم إنشاء إعداد WireGuard الخاص بك.\n"
                    f"IP: `{address}`\n"
                    "استورد الملف في تطبيق WireGuard."
                ),
                file=discord.File(
                    str(config_path),
                    filename="vpn.conf",
                ),
                ephemeral=True,
            )

        except Exception as exc:
            print(f"[VPN ERROR] {type(exc).__name__}: {exc}")

            if isinstance(exc, RuntimeError):
                message = str(exc)

                if "WG_SERVER_PUBLIC_KEY" in message:
                    reason = "إعداد مفتاح السيرفر غير موجود."
                elif "WG_ENDPOINT" in message:
                    reason = "عنوان السيرفر غير مضبوط."
                elif "No free WireGuard client IP addresses" in message:
                    reason = "لا توجد عناوين VPN متاحة."
                else:
                    reason = message

                await interaction.followup.send(
                    f"فشل إنشاء VPN: `{reason}`",
                    ephemeral=True,
                )
            else:
                await interaction.followup.send(
                    f"فشل إنشاء VPN: `{type(exc).__name__}`",
                    ephemeral=True,
                )
