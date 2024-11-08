import logging

from feast.errors import FeastPermissionError
from feast.feast_object import FeastObject
#from feast.permissions.decision import DecisionEvaluator
from feast.permissions.permission import (
    AuthzedAction,
    Permission,
)
from feast.permissions.user import User

logger = logging.getLogger(__name__)


def enforce_policy(
    permissions: list[Permission],
    user: User,
    resources: list[FeastObject],
    actions: list[AuthzedAction],
    filter_only: bool = False,
) -> list[FeastObject]:
    """
    Define the logic to apply the configured permissions when a given action is requested on
    a protected resource.

    If no permissions are defined, the result is to deny the execution.

    Args:
        permissions: The configured set of `Permission`.
        user: The current user.
        resources: The resources for which we need to enforce authorized permission.
        actions: The requested actions to be authorized.
        filter_only: If `True`, it removes unauthorized resources from the returned value, otherwise it raises a `FeastPermissionError` the
        first unauthorized resource. Defaults to `False`.

    Returns:
        list[FeastObject]: A filtered list of the permitted resources.

    Raises:
        FeastPermissionError: If the current user is not authorized to eecute the requested actions on the given resources (and `filter_only` is `False`).
    """
    if not permissions:
        return resources

    _permitted_resources: list[FeastObject] = []
    for resource in resources:
        logger.debug(
            f"Enforcing permission policies for {type(resource).__name__}:{resource.name} to execute {actions}"
        )

        resource_permissions = [p for p in permissions if p in resource.permissions]
        matching_permissions = []
        denial_explanations = []

        for p in resource_permissions:
            permission_grant, permission_explanation = p.policy.validate_user(
                    user=user
                )
            if permission_grant:
                matching_permissions.append(p)
            else:
                denial_explanations.append(f"Permission {p.name} denied for a reason: {permission_explanation}")

        matching_permissions = [p for p in matching_permissions if p.match_actions(actions)]

        if matching_permissions:
            _permitted_resources.append(resource)
        else:
            message = f"No permissions defined to manage {actions} on {type(resource)}/{resource.name}."
            logger.exception(f"**PERMISSION NOT GRANTED**: {message}")
            raise FeastPermissionError(message)
    return _permitted_resources
