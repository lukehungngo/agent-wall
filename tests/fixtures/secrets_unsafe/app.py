import logging

API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

client = SomeClient(api_key="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")  # noqa: F821

logger = logging.getLogger(__name__)


def process():
    chat_history = get_history()  # noqa: F821
    logger.debug(f"History: {chat_history}")
    print(messages)  # noqa: F821
