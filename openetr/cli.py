import click
from openetr.commands.core import alias_group, bootstrap, get_object_id, info, init_config, migrate_config, profile_group, set_config, trivia, validate, version, whoami
from openetr.commands.publish import issue_etr, publish_object, publish_profile, terminate_etr, transfer_group
from openetr.commands.query import query_etr, query_object, query_profile, verify
from openetr.config import HOME_RELAY_KEY, ROOT_NSEC_KEY, USER_CONFIG_PATH, ensure_root_bootstrap


@click.group(invoke_without_command=True)
@click.option("--as-root", default=None, help="Use this root nsec for this invocation without relying on local bootstrap.")
@click.option(
    "--home-relays",
    default=None,
    help="Use these comma-separated home relays for this invocation without relying on local bootstrap.",
)
@click.pass_context
def main(ctx: click.Context, as_root: str | None, home_relays: str | None) -> None:
    """OpenETR command line utility."""
    ctx.ensure_object(dict)
    if as_root:
        ctx.obj[ROOT_NSEC_KEY] = as_root
    if home_relays:
        ctx.obj[HOME_RELAY_KEY] = home_relays

    has_runtime_bootstrap = bool(as_root and home_relays)

    if ctx.invoked_subcommand in {"init-config", "bootstrap"}:
        return

    if not USER_CONFIG_PATH.exists() and not has_runtime_bootstrap:
        if ctx.invoked_subcommand is None:
            click.secho("No OpenETR bootstrap config was found.", fg="yellow", bold=True, err=True)
            click.echo(f"Expected bootstrap file: {USER_CONFIG_PATH}", err=True)
            click.echo(
                "If you already know the root nsec and home relays for this OpenETR environment, "
                "use: openetr bootstrap --root-nsec <nsec> --home-relays <relay[,relay]>",
                err=True,
            )
            click.confirm(
                "Do you want to continue and create a new bootstrap config now?",
                default=True,
                abort=True,
                err=True,
            )
            click.echo("Starting bootstrap setup...", err=True)
            ctx.invoke(bootstrap, root_nsec=None, home_relays=None, force=False)
            return

        click.secho("No OpenETR bootstrap config was found.", fg="yellow", bold=True, err=True)
        click.echo(f"Expected bootstrap file: {USER_CONFIG_PATH}", err=True)
        click.echo(
            "If you already know the root nsec and home relays for this OpenETR environment, "
            "abort and run: openetr bootstrap --root-nsec <nsec> --home-relays <relay[,relay]>",
            err=True,
        )
        click.confirm(
            "Create a new bootstrap config now and continue?",
            default=True,
            abort=True,
            err=True,
        )

    _, changes = ensure_root_bootstrap()
    if changes.get(ROOT_NSEC_KEY):
        click.secho("Initialized root CLI identity.", fg="yellow", bold=True, err=True)
        click.echo(f"Root nsec: {changes[ROOT_NSEC_KEY]}", err=True)
        if changes.get("root_recovery_phrase"):
            click.echo("Recovery phrase:", err=True)
            click.echo(f"  {changes['root_recovery_phrase']}", err=True)
        elif changes.get("root_recovery_phrase_unavailable"):
            click.echo(
                "Recovery phrase unavailable until the optional 'mnemonic' dependency is installed.",
                err=True,
            )
    if changes.get(HOME_RELAY_KEY):
        click.secho(
            f"Set home relays to {changes[HOME_RELAY_KEY]}.",
            fg="yellow",
            bold=True,
            err=True,
        )


profile_group.add_command(publish_profile, "publish")

main.add_command(version)
main.add_command(info)
main.add_command(whoami)
main.add_command(get_object_id)
main.add_command(validate)
main.add_command(init_config)
main.add_command(bootstrap)
main.add_command(migrate_config)
main.add_command(alias_group)
main.add_command(profile_group)
main.add_command(set_config)
main.add_command(trivia)
main.add_command(publish_object)
main.add_command(issue_etr)
main.add_command(terminate_etr)
main.add_command(transfer_group)
main.add_command(query_etr)
main.add_command(query_object)
main.add_command(query_profile)
main.add_command(verify)
