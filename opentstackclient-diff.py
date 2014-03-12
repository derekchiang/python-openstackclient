diff --git a/openstackclient/common/clientmanager.py b/openstackclient/common/clientmanager.py
index b6dab25..df09a8c 100644
--- a/openstackclient/common/clientmanager.py
+++ b/openstackclient/common/clientmanager.py
@@ -45,7 +45,7 @@ class ClientManager(object):
     def __init__(self, token=None, url=None, auth_url=None,
                  domain_id=None, domain_name=None,
                  project_name=None, project_id=None,
-                 username=None, password=None,
+                 username=None, password=None, tfa_password=None,
                  user_domain_id=None, user_domain_name=None,
                  project_domain_id=None, project_domain_name=None,
                  region_name=None, api_version=None, verify=True):
@@ -58,6 +58,7 @@ class ClientManager(object):
         self._project_id = project_id
         self._username = username
         self._password = password
+        self._tfa_password = tfa_password
         self._user_domain_id = user_domain_id
         self._user_domain_name = user_domain_name
         self._project_domain_id = project_domain_id
diff --git a/openstackclient/identity/v3/user.py b/openstackclient/identity/v3/user.py
index 060eeca..7b24415 100644
--- a/openstackclient/identity/v3/user.py
+++ b/openstackclient/identity/v3/user.py
@@ -318,6 +318,19 @@ class SetUser(command.Command):
             action='store_true',
             help='Disable user',
         )
+        enable_tfa_group = parser.add_mutually_exclusive_group()
+        enable_tfa_group.add_argument(
+            '--enable-tfa',
+            dest="enable_tfa",
+            action='store_true',
+            help='Enable two-factor authentication for user',
+        )
+        enable_tfa_group.add_argument(
+            '--disable-tfa',
+            dest="disable_tfa",
+            action='store_true',
+            help='Disable two-factor authentication for user',
+        )
         return parser
 
     def take_action(self, parsed_args):
@@ -335,7 +348,9 @@ class SetUser(command.Command):
                 and not parsed_args.project
                 and not parsed_args.description
                 and not parsed_args.enable
-                and not parsed_args.disable):
+                and not parsed_args.disable
+                and not parsed_args.enable_tfa
+                and not parsed_args.disable_tfa):
             return
 
         user = utils.find_resource(
@@ -365,8 +380,22 @@ class SetUser(command.Command):
             kwargs['enabled'] = True
         if parsed_args.disable:
             kwargs['enabled'] = False
+        kwargs['tfa_enabled'] = getattr(user, 'tfa_enabled', False)
+        if parsed_args.enable_tfa:
+            kwargs['tfa_enabled'] = True
+        if parsed_args.disable_tfa:
+            kwargs['tfa_enabled'] = False
+
+        # TODO: From this point on, we need to touch the server side.
+        # You need to modify the controller such that it returns a "secret"
+        # and then, the update() call should return a dictionary that contains
+        # this secret.  Then you would output the secret on the terminal,
+        # so that the user can register.
+        res = identity_client.users.update(user.id, **kwargs)
+        self.app.stdout.write(
+            'Please enter the following secret into your TFA client: %s'
+            % res.get('secret', '1234567'))  # TODO: this is for demo purpose
 
-        identity_client.users.update(user.id, **kwargs)
         return
 
 
diff --git a/openstackclient/shell.py b/openstackclient/shell.py
index 4930799..31da52f 100644
--- a/openstackclient/shell.py
+++ b/openstackclient/shell.py
@@ -194,6 +194,11 @@ class OpenStackShell(app.App):
             default=utils.env('OS_PASSWORD'),
             help='Authentication password (Env: OS_PASSWORD)')
         parser.add_argument(
+            '--os-tfa-password',
+            metavar='<auth-tfa-password>',
+            default=None,
+            help='Two-factor authentication password')
+        parser.add_argument(
             '--os-user-domain-name',
             metavar='<auth-user-domain-name>',
             default=utils.env('OS_USER_DOMAIN_NAME'),
@@ -354,6 +359,7 @@ class OpenStackShell(app.App):
             project_domain_name=self.options.os_project_domain_name,
             username=self.options.os_username,
             password=self.options.os_password,
+            tfa_password=self.options.os_tfa_password,
             region_name=self.options.os_region_name,
             verify=self.verify,
             api_version=self.api_version,
