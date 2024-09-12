FIND_PACKAGE(CURL)
IF(NOT CURL_FOUND)
  # Can't build plugin
  MESSAGE_ONCE(WARNING "Onboardbase Key Management plugin requires curl development package")
  RETURN()
ENDIF()

SET_PACKAGE_PROPERTIES(CURL PROPERTIES TYPE REQUIRED)

INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIRS})

set(CPACK_RPM_onboardbase-key-management_PACKAGE_SUMMARY "Onboardbase Key Management plugin for MariaDB" PARENT_SCOPE)
set(CPACK_RPM_onboardbase-key-management_PACKAGE_DESCRIPTION "This encryption plugin uses Onboardbase Store for storing encryption
 keys for MariaDB Data-at-Rest encryption." PARENT_SCOPE)

MYSQL_ADD_PLUGIN(ONBOARDBASE_KEY_MANAGEMENT
  onboardbase_key_management_plugin.cc
  LINK_LIBRARIES ${CURL_LIBRARIES}
  CONFIG onboardbase_key_management.cnf
  COMPONENT onboardbase-key-management
  MODULE_ONLY)

ADD_FEATURE_INFO(ONBOARDBASE_KEY_MANAGEMENT "ON" "Onboardbase Key Management Plugin")
