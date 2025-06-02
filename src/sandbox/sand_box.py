import logging
from daytona_sdk import Daytona, DaytonaConfig, CreateSandboxParams, Sandbox, SessionExecuteRequest

from src.sandbox import config
from src.sandbox.config import Configuration

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

daytona_config = DaytonaConfig(
    api_key="dtn_14033978ed8214ab78d3993007b8bd1cdcb0eac6dcb9cd6cac609049c8d2161e"
)

daytona = Daytona(daytona_config)
def create_sandbox(password: str, project_id: str = None):
    """Create a new sandbox with all required services configured and running."""

    logger.debug("Creating new Daytona sandbox environment")
    logger.debug("Configuring sandbox with browser-use image and environment variables")

    labels = None
    if project_id:
        logger.debug(f"Using sandbox_id as label: {project_id}")
        labels = {'id': project_id}

    params = CreateSandboxParams(
        image=Configuration.SANDBOX_IMAGE_NAME,
        public=True,
        labels=labels,
        env_vars={
            "CHROME_PERSISTENT_SESSION": "true",
            "RESOLUTION": "1024x768x24",
            "RESOLUTION_WIDTH": "1024",
            "RESOLUTION_HEIGHT": "768",
            "VNC_PASSWORD": password,
            "ANONYMIZED_TELEMETRY": "false",
            "CHROME_PATH": "",
            "CHROME_USER_DATA": "",
            "CHROME_DEBUGGING_PORT": "9222",
            "CHROME_DEBUGGING_HOST": "localhost",
            "CHROME_CDP": ""
        },
        resources={
            "cpu": 2,
            "memory": 4,
            "disk": 5,
        }
    )

    # Create the sandbox
    sandbox = daytona.create(params)
    logger.debug(f"Sandbox created with ID: {sandbox.id}")

    # Start supervisord in a session for new sandbox
    # start_supervisord_session(sandbox)

    logger.debug(f"Sandbox environment successfully initialized")
    return sandbox

create_sandbox("test_password", "test_project_id")