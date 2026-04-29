import click
from openetr.commands.core import get_object_id, info, init_config, profile_group, set_config, trivia, validate, version, whoami
from openetr.commands.publish import issue_etr, publish_object, publish_profile, transfer_group
from openetr.commands.query import query_etr, query_object, query_profile, verify


@click.group()
def main() -> None:
    """OpenETR command line utility."""


main.add_command(version)
main.add_command(info)
main.add_command(whoami)
main.add_command(get_object_id)
main.add_command(validate)
main.add_command(init_config)
main.add_command(profile_group)
main.add_command(set_config)
main.add_command(trivia)
main.add_command(publish_object)
main.add_command(issue_etr)
main.add_command(publish_profile)
main.add_command(transfer_group)
main.add_command(query_etr)
main.add_command(query_object)
main.add_command(query_profile)
main.add_command(verify)
