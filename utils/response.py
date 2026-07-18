def success_response(data):
    """
    Creates a standard success response.
    """

    return {
        "success": True,
        "data": data,
        "error": None
    }


def error_response(message):
    """
    Creates a standard error response.
    """

    return {
        "success": False,
        "data": None,
        "error": message
    }