"""
Block URL action for iBoss Google SecOps SOAR Integration.

Blocks a given URL in the iBoss Cloud Gateway blocklist.
"""

from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.IBossManager import (
    IBossAuthenticationError,
    IBossConnectionError,
    IBossManager,
)
from ..core.constants import (
    INTEGRATION_DISPLAY_NAME,
    INTEGRATION_NAME,
    BLOCK_URL_SCRIPT_NAME,
)

@output_handler
def main() -> None:
    """Main execution logic for the Block URL action."""
    siemplify = SiemplifyAction()
    siemplify.script_name = BLOCK_URL_SCRIPT_NAME
    siemplify.LOGGER.info(f"Action: {BLOCK_URL_SCRIPT_NAME} started")

    iboss_username = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="iboss_username",
        is_mandatory=True,
    )
    iboss_password = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="iboss_password",
        is_mandatory=True,
    )
    
    url_to_block = siemplify.extract_action_param(
        param_name="url", 
        is_mandatory=True, 
        print_value=True
    )
    note = siemplify.extract_action_param(
        param_name="note", 
        is_mandatory=False, 
        default_value="Blocked via Chronicle Action", 
        print_value=True
    )

    result_value = False
    status = EXECUTION_STATE_FAILED

    try:
        siemplify.LOGGER.info(f"Connecting to {INTEGRATION_DISPLAY_NAME}...")
        manager = IBossManager(username=iboss_username, password=iboss_password)
        manager.connect()
        
        siemplify.LOGGER.info(f"Attempting to block URL: {url_to_block}")
        manager.block_url(url=url_to_block, note=note)
        
        output_message = f"Successfully submitted blocklist request for {url_to_block}."
        result_value = True
        status = EXECUTION_STATE_COMPLETED

    except (IBossAuthenticationError, IBossConnectionError, Exception) as e:
        output_message = f"Failed to block URL: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}  Result: {result_value}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
