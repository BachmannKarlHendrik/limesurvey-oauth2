<?php

/* @version 1.4.4 */

require_once(__DIR__ . '/vendor/autoload.php');
use League\OAuth2\Client\Provider\GenericProvider;
use LimeSurvey\PluginManager\AuthPluginBase;
use LimeSurvey\PluginManager\LimesurveyApi;
use LimeSurvey\PluginManager\PluginEvent;
use LimeSurvey\PluginManager\PluginManager;


class AuthOAuth2 extends AuthPluginBase
{
    protected const SESSION_STATE_KEY = 'oauth_auth_state';

    protected $storage = 'DbStorage';
    protected static $name = 'OAuth2 Authentication';
    protected static $description = 'Enable Single Sign-On using OAuth2';

    protected $resourceData = [];

    /* @var array Check getPluginSettings */
    protected $settings = [];

    public function init(): void
    {
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('newLoginForm');
        $this->subscribe('getGlobalBasePermissions');
    }

    /**
     * @see parent:getPluginSettings
     * @param mixed $getValues
     */
    public function getPluginSettings($getValues = true)
    {
        if (!Permission::model()->hasGlobalPermission('settings', 'read')) {
            throw new CHttpException(403);
        }
        /* Definition and default */
        $fixedPluginSettings = $this->getFixedGlobalSetting();
        $this->settings = [
            'client_id' => [
                'type' => 'string',
                'label' => $this->gT('Client ID'),
                'default' => $this->getGlobalSetting('client_id'),
                'htmlOptions' => [
                    'readonly' => in_array('client_id', $fixedPluginSettings)
                ]
            ],
            'client_secret' => [
                'type' => 'string',
                'label' => $this->gT('Client Secret'),
                'default' => $this->getGlobalSetting('client_secret'),
                'htmlOptions' => [
                    'readonly' => in_array('client_secret', $fixedPluginSettings)
                ]
            ],
            'redirect_uri' => [
                'type' => 'info',
                'label' => $this->gT('Redirect URI'),
                'content' => CHtml::tag(
                    'input',
                    [
                        'type' => 'text',
                        'class' => 'form-control',
                        'readonly' => true,
                        'value' => $this->api->createUrl('admin/authentication/sa/login', []),
                    ]
                ),
            ],
            'authorize_url' => [
                'type' => 'string',
                'label' => $this->gT('Authorize URL'),
                'default' => $this->getGlobalSetting('authorize_url'),
                'htmlOptions' => [
                    'readonly' => in_array('authorize_url', $fixedPluginSettings)
                ]
            ],
            'scopes' => [
                'type' => 'string',
                'label' => $this->gT('Scopes'),
                'help' => $this->gT('Comma-separated list of scopes to use for authorization.'),
                'default' => $this->getGlobalSetting('scopes'),
                'htmlOptions' => [
                    'readonly' => in_array('scopes', $fixedPluginSettings)
                ]
            ],
            'scope_separator' => [
                'type' => 'string',
                'label' => $this->gT('Scopes separator in URL'),
                'help' => $this->gT('Separate scopes in authorization URL.'),
                'default' => $this->getGlobalSetting('scope_separator', ','),
                'htmlOptions' => [
                    'readonly' => in_array('scope_separator', $fixedPluginSettings)
                ]
            ],
            'access_token_url' => [
                'type' => 'string',
                'label' => $this->gT('Access Token URL'),
                'default' => $this->getGlobalSetting('access_token_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('access_token_url', $fixedPluginSettings)
                ]
            ],
            'resource_owner_details_url' => [
                'type' => 'string',
                'label' => $this->gT('User Details URL'),
                'help' => $this->gT('URL to load the user details from using the retrieved access token.'),
                'default' => $this->getGlobalSetting('resource_owner_details_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('resource_owner_details_url', $fixedPluginSettings)
                ]
            ],
            'identifier_attribute' => [
                'type' => 'select',
                'label' => $this->gT('Identifier Attribute'),
                'help' => $this->gT('Attribute of the LimeSurvey user to match against.'),
                'options' => [
                    'username' => $this->gT('Username'),
                    'email' => $this->gT('E-Mail'),
                ],
                'default' => $this->getGlobalSetting('identifier_attribute', 'username'),
                'htmlOptions' => [
                    'disabled' => in_array('identifier_attribute', $fixedPluginSettings)
                ],
                'selectOptions' => [
                    'disabled' => in_array('identifier_attribute', $fixedPluginSettings)
                ]
            ],
            'username_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for username in user details'),
                'help' => $this->gT('Key for the username in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('username_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('username_key', $fixedPluginSettings)
                ]
            ],
            'email_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for e-mail in user details'),
                'help' => $this->gT('Key for the e-mail in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('email_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('email_key', $fixedPluginSettings)
                ]
            ],
            'display_name_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for display name in user details'),
                'help' => $this->gT('Key for the full name in the user details data. Only required if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('display_name_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('display_name_key', $fixedPluginSettings)
                ]
            ],
            'is_default' => [
                'type' => 'checkbox',
                'label' => $this->gT('Use as default login'),
                'help' => sprintf(
                    '%s<br>%s',
                    $this->gT('If enabled instead of showing the LimeSurvey login the user is redirected directly to the OAuth2 login. The default login form can always be accessed via:'),
                    htmlspecialchars($this->api->createUrl('admin/authentication/sa/login', ['authMethod' => 'Authdb']))
                ),
                'default' => $this->getGlobalSetting('is_default', false),
                'htmlOptions' => [
                    'disabled' => in_array('is_default', $fixedPluginSettings)
                ]
            ],
            'autocreate_users' => [
                'type' => 'checkbox',
                'label' => $this->gT('Create new users'),
                'help' => $this->gT('If enabled users that do not exist yet will be created in LimeSurvey after successfull login.'),
                'default' => $this->getGlobalSetting('autocreate_users', false),
                'htmlOptions' => [
                    'disabled' => in_array('autocreate_users', $fixedPluginSettings)
                ]
            ],
            'introduction_text' => [
                'type' => 'string',
                'label' => $this->gT('Introduction to the OAuth login button.'),
                'default' => $this->getGlobalSetting('introduction_text', ''),
                'htmlOptions' => [
                    'placeholder' => $this->gT('Login with Oauth2'),
                    'readonly' => in_array('introduction_text', $fixedPluginSettings)
                ]
            ],
            'button_text' => [
                'type' => 'string',
                'label' => $this->gT('Text on login button.'),
                'default' => $this->getGlobalSetting('button_text', ''),
                'htmlOptions' => [
                    'placeholder' => $this->gT('Login'),
                    'readonly' => in_array('button_text', $fixedPluginSettings)
                ]
            ],
        ];

        if (method_exists(Permissiontemplates::class, 'applyToUser')) {
            $roles = [];
            foreach (Permissiontemplates::model()->findAll() as $role) {
                $roles[$role->ptid] = $role->name;
            }

            $this->settings['autocreate_roles'] = [
                'type' => 'select',
                'label' => $this->gT('Global roles for new users'),
                'help' => $this->gT('Global user roles to be assigned to users that are automatically created.'),
                'options' => $roles,
                'htmlOptions' => [
                    'multiple' => true,
                    'disabled' => in_array('autocreate_roles', $fixedPluginSettings)
                ],
                'default' => $this->getGlobalSetting('autocreate_roles', ''),
                'selectOptions' => [
                    'disabled' => in_array('autocreate_roles', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_key'] = [
                'type' => 'string',
                'label' => $this->gT('Key for roles in user detail'),
                'help' => $this->gT('Key to get the user roles. Must be an array, if roles exist : it was assigned to the user when it was created.'),
                'default' => $this->getGlobalSetting('roles_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('roles_key', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_update'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Update roles at each log in'),
                'help' => $this->gT('Check and update roles each time an user log in.'),
                'default' => $this->getGlobalSetting('roles_update', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_update', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_needed'] = [
                'type' => 'string',
                'label' => $this->gT('Need a minimum one role to allow log in or create user.'),
                'help' => $this->gT('If user didn\'t have any roles : disallow log in. Roles name are not checked with existing role.'),
                'default' => $this->getGlobalSetting('roles_needed', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_needed', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_removetext'] = [
                'type' => 'string',
                'label' => $this->gT('Allow you to remove specific string on the roles returnned'),
                'help' => $this->gT('This string was removed to the roles returned before comparaison.'),
                'default' => $this->getGlobalSetting('roles_removetext', ''),
                'htmlOptions' => [
                    'readonly' => in_array('roles_removetext', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_insensitive'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Insensitive comparaison for roles'),
                'help' => $this->gT('Do an insensitive comparaison before search the roles.'),
                'default' => $this->getGlobalSetting('roles_insensitive', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_insensitive', $fixedPluginSettings)
                ]
            ];
        }

        $this->settings['autocreate_permissions'] = [
            'type' => 'json',
            'label' => $this->gT('Global permissions for new users'),
            'help' => sprintf(
                $this->gT('A JSON object describing the default permissions to be assigned to users that are automatically created. The JSON object has the following form: %s'),
                CHtml::tag('pre', [], "{\n\t\"surveys\": { ... },\n\t\"templates\": {\n\t\t\"create\": false,\n\t\t\"read\": false,\n\t\t\"update\": false,\n\t\t\"delete\": false,\n\t\t\"import\": false,\n\t\t\"export\": false,\n\t},\n\t\"users\": { ... },\n\t...\n}")
            ),
            'editorOptions' => array('mode' => 'tree'),
            'default' => $this->getGlobalSetting(
                'autocreate_permissions',
                self::getDefaultPermission()
            ),
            'htmlOptions' => [
                'disabled' => in_array('autocreate_permissions', $fixedPluginSettings)
            ],
        ];
        /* Get current */
        $pluginSettings = parent::getPluginSettings($getValues);
        /* Update current for fixed one */
        if ($getValues) {
            foreach ($fixedPluginSettings as $setting) {
                $pluginSettings[$setting]['current'] = $this->getGlobalSetting($setting);
            }
        }
        /* Remove hidden */
        foreach ($this->getHiddenGlobalSetting() as $setting) {
            unset($pluginSettings[$setting]);
        }
        return $pluginSettings;
    }

    public function newLoginForm()
    {
        $oEvent = $this->getEvent();
        $introductionText = viewHelper::purified(trim($this->getGlobalSetting('introduction_text')));
        if (empty($introductionText)) {
            $introductionText = $this->gT("Login with Oauth2");
        }
        $buttonText = viewHelper::purified(trim($this->getGlobalSetting('button_text')));
        if (empty($buttonText)) {
            $buttonText = $this->gT("Login");
        }
        $aData = [
            'introductionText' => $introductionText,
            'buttonText' => $buttonText,
        ];
        $authContent = $content = $this->renderPartial('admin.authentication.Oauth2LoginButton', $aData, true);
        $allFromsContent = $oEvent->getAllContent();
        foreach ($allFromsContent as $plugin => $content) {
            $oEvent->getContent($plugin)->addContent($authContent, 'prepend');
        }
    }

    /**
     * @throws CHttpException
     */
    public function beforeLogin()
    {
        error_log('OAuth2: Starting beforeLogin');
        $request = $this->api->getRequest();
        if ($error = $request->getParam('error')) {
            error_log('OAuth2: Error in request params: ' . $error);
            throw new CHttpException(401, $request->getParam('error_description', $error));
        }

        error_log('OAuth2: Creating provider with client_id: ' . $this->getGlobalSetting('client_id'));
        $provider = new GenericProvider([
            'clientId' => $this->getGlobalSetting('client_id'),
            'clientSecret' => $this->getGlobalSetting('client_secret'),
            'redirectUri' => $this->api->createUrl('admin/authentication/sa/login', []),
            'urlAuthorize' => $this->getGlobalSetting('authorize_url'),
            'urlAccessToken' => $this->getGlobalSetting('access_token_url'),
            'urlResourceOwnerDetails' => $this->getGlobalSetting('resource_owner_details_url'),
            'scopeSeparator' => $this->getGlobalSetting('scope_separator'),
            'scopes' => array_map(
                function ($scope) {
                    return trim($scope);
                },
                explode(',', $this->getGlobalSetting('scopes', ''))
            ),
        ]);

        $code = $request->getParam('code');
        error_log('OAuth2: Auth code from request: ' . ($code ? 'present' : 'missing'));
        
        $defaultAuth = $this->getGlobalSetting('is_default') ? self::class : null;
        error_log('OAuth2: Default auth method: ' . ($defaultAuth ? $defaultAuth : 'none'));
        error_log('OAuth2: Requested auth method: ' . $request->getParam('authMethod', $defaultAuth));
        
        if (empty($code) && $request->getParam('authMethod', $defaultAuth) !== self::class) {
            error_log('OAuth2: No code and not OAuth2 auth method, returning');
            return;
        }

        if (empty($code)) {
            error_log('OAuth2: No code, redirecting to authorization URL');
            $authorizationUrl = $provider->getAuthorizationUrl();
            Yii::app()->session->add(self::SESSION_STATE_KEY, $provider->getState());
            error_log('OAuth2: State saved to session: ' . $provider->getState());
            $request->redirect($authorizationUrl);
        }

        $state = $request->getParam('state');
        $safedState = Yii::app()->session->get(self::SESSION_STATE_KEY);
        error_log('OAuth2: State validation - Received: ' . $state . ', Saved: ' . $safedState);
        
        if ($state !== $safedState) {
            error_log('OAuth2: State mismatch - throwing exception');
            throw new CHttpException(400, $this->gT('Invalid state in OAuth response'));
        }

        Yii::app()->session->remove(self::SESSION_STATE_KEY);
        error_log('OAuth2: State removed from session');

        try {
            error_log('OAuth2: Attempting to get access token');
            $accessToken = $provider->getAccessToken('authorization_code', ['code' => $code]);
            error_log('OAuth2: Successfully got access token');
        } catch (Throwable $exception) {
            error_log('OAuth2: Failed to get access token - ' . $exception->getMessage());
            throw new CHttpException(400, $this->gT('Failed to retrieve access token'));
        }

        try {
            error_log('OAuth2: Attempting to get resource owner details');
            $resourceOwner = $provider->getResourceOwner($accessToken);
            $this->resourceData = $resourceOwner->toArray();
            error_log('OAuth2: Successfully got resource owner details: ' . json_encode($this->resourceData));
        } catch (Throwable $exception) {
            error_log('OAuth2: Failed to get user details - ' . $exception->getMessage());
            throw new CHttpException(400, $this->gT('Failed to retrieve user details'));
        }

        if ($this->getGlobalSetting('identifier_attribute') === 'email') {
            $identifierKey = $this->getGlobalSetting('email_key');
            error_log('OAuth2: Using email as identifier with key: ' . $identifierKey);
        } else {
            $identifierKey = $this->getGlobalSetting('username_key');
            error_log('OAuth2: Using username as identifier with key: ' . $identifierKey);
        }
        
        $userIdentifier = $this->getTemplatedKey($identifierKey);
        error_log('OAuth2: Extracted user identifier: ' . $userIdentifier);

        if (empty($userIdentifier)) {
            error_log('OAuth2: User identifier is empty');
            throw new CHttpException(400, 'User identifier not found or empty');
        }
        
        error_log('OAuth2: Setting username and auth plugin');
        $this->setUsername($userIdentifier);
        $this->setAuthPlugin();
    }

    /**
     * @throws CHttpException
     */
    public function newUserSession()
    {
        error_log('OAuth2: Starting newUserSession');
        $userIdentifier = $this->getUserName();
        error_log('OAuth2: User identifier from session: ' . $userIdentifier);
        
        $identity = $this->getEvent()->get('identity');
        error_log('OAuth2: Identity plugin: ' . $identity->plugin . ', Username: ' . $identity->username);
        
        if ($identity->plugin != self::class || $identity->username !== $userIdentifier) {
            error_log('OAuth2: Identity mismatch - returning');
            return;
        }
        
        $oIdentityEvent = $this->getEvent();

        if ($this->getGlobalSetting('identifier_attribute') === 'email') {
            error_log('OAuth2: Looking up user by email');
            $user = $this->api->getUserByEmail($userIdentifier);
        } else {
            error_log('OAuth2: Looking up user by username');
            $user = $this->api->getUserByName($userIdentifier);
        }

        error_log('OAuth2: User found: ' . ($user ? 'yes' : 'no'));
        error_log('OAuth2: Autocreate users setting: ' . ($this->getGlobalSetting('autocreate_users') ? 'enabled' : 'disabled'));

        if (!$user && !$this->getGlobalSetting('autocreate_users')) {
            error_log('OAuth2: User not found and autocreate disabled');
            if ($this->getGlobalSetting('is_default')) {
                error_log('OAuth2: Throwing 403 as default auth method');
                throw new CHttpException(403, gT('Incorrect username and/or password!'));
            } else {
                error_log('OAuth2: Setting auth failure');
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                return;
            }
        }

        if ($this->getGlobalSetting('roles_needed', false) && $rolesKey = $this->getGlobalSetting('roles_key', '')) {
            error_log('OAuth2: Checking roles with key: ' . $rolesKey);
            $aRoles = $this->getNestedArrayData($rolesKey);
            error_log('OAuth2: Found roles: ' . json_encode($aRoles));
            
            if (empty($aRoles)) {
                error_log('OAuth2: No roles found');
                if ($this->getGlobalSetting('is_default')) {
                    error_log('OAuth2: Throwing 403 as default auth method');
                    throw new CHttpException(403, gT('Incorrect username and/or password!'));
                } else {
                    error_log('OAuth2: Setting auth failure');
                    $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                    return;
                }
            }
        }

        if (!$user) {
            error_log('OAuth2: Creating new user');
            $this->unsubscribe('getGlobalBasePermissions');

            $usernameKey = $this->getGlobalSetting('username_key');
            $username = $this->getTemplatedKey($usernameKey);
            $displayNameKey = $this->getGlobalSetting('display_name_key');
            $displayName = $this->getTemplatedKey($displayNameKey, ' ');
            $emailKey = $this->getGlobalSetting('email_key');
            $email = $this->getTemplatedKey($emailKey);

            error_log('OAuth2: New user details - Username: ' . $username . ', Email: ' . $email);

            $user = new User();
            $user->parent_id = 1;
            $user->setPassword(createPassword());

            $user->users_name = $username;
            $user->full_name = $displayName;
            $user->email = $email;

            if (!$user->save()) {
                error_log('OAuth2: Failed to save new user - ' . json_encode($user->getErrors()));
                throw new CHttpException(401, $this->gT('Failed to create new user'));
            }
            error_log('OAuth2: New user created successfully');

            $defaultPermissions = @json_decode($this->getGlobalSetting('autocreate_permissions', self::getDefaultPermission()), true);
            if (!empty($defaultPermissions)) {
                error_log('OAuth2: Setting default permissions');
                Permission::setPermissions($user->uid, 0, 'global', $defaultPermissions, true);
            }

            error_log('OAuth2: Setting OAuth permission');
            self::setOauthPermission($user->uid, true);

            if (method_exists(Permissiontemplates::class, 'applyToUser')) {
                $autocreateRoles = $this->getGlobalSetting('autocreate_roles');
                if (!empty($autocreateRoles)) {
                    error_log('OAuth2: Setting auto-created roles: ' . json_encode($autocreateRoles));
                    foreach ($autocreateRoles as $role) {
                        Permissiontemplates::model()->applyToUser($user->uid, $role);
                    }
                }
                error_log('OAuth2: Setting roles to user');
                $this->setRolesToUser($user->uid);
            }

            $this->setUsername($user->users_name);
            error_log('OAuth2: Setting auth success for new user');
            $this->setAuthSuccess($user, $oIdentityEvent);
        } else {
            error_log('OAuth2: Existing user found, checking permissions');
            
            if ($this->getGlobalSetting('roles_update', false)) {
                error_log('OAuth2: Updating roles for existing user');
                UserInPermissionrole::model()->deleteAll("uid = :uid", [':uid' => $user->uid]);
                $this->setRolesToUser($user->uid);
            }

            error_log('OAuth2: Checking auth_oauth permission');
            if (!Permission::model()->hasGlobalPermission('auth_oauth', 'read', $user->uid)) {
                error_log('OAuth2: User does not have auth_oauth permission');
                $permissionnExist = Permission::model()->findByAttributes([
                    'entity_id' => 0,
                    'entity' => 'global',
                    'uid' => $user->uid,
                    'permission' => 'auth_oauth'
                ]);
                
                if (empty($permissionnExist)) {
                    error_log('OAuth2: Creating auth_oauth permission');
                    Permission::model()->setGlobalPermission($user->uid, 'auth_oauth');
                } else {
                    error_log('OAuth2: Permission exists but not granted');
                    if ($this->getGlobalSetting('is_default')) {
                        error_log('OAuth2: Throwing 403 as default auth method');
                        throw new CHttpException(403, gT('Incorrect username and/or password!'));
                    } else {
                        error_log('OAuth2: Setting auth failure');
                        $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                        return;
                    }
                }
            } else {
                error_log('OAuth2: User has auth_oauth permission');
            }

            $this->setUsername($user->users_name);
            error_log('OAuth2: Setting auth success for existing user');
            $this->setAuthSuccess($user);
        }
    }

    public function getGlobalBasePermissions(): void
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_oauth' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => "Use OAuth authentication",
                'description' => "Use OAuth authentication",
                'img' => 'fa fa-user-circle-o'
            ),
        ));
    }

    /**
     * @param string $iKey
     * @param string $iSeparator
     * @return string
     */
    public function getTemplatedKey(string $iKey, string $iSeparator = '.'): string
    {
        $rValue = '';
        if (str_contains($iKey, '.') || str_contains($iKey, '+')) {
            $newUsernameKey = '';
            $sub_values = array_map(
                function ($sub_key) {
                    $sub_key_modified = $sub_key;
                    $value = '';
                    if (str_contains($sub_key, '.')) {
                        $sub_key_as_table = explode('.', $sub_key);
                        $sub_key_modified = $sub_key_as_table[0];
                        
                        // Handle nested paths with | for better access to nested JSON
                        if (str_contains($sub_key_modified, '|')) {
                            $segments = explode('|', $sub_key_modified);
                            $tempValue = $this->resourceData;
                            foreach ($segments as $segment) {
                                if (!isset($tempValue[$segment])) {
                                    throw new CHttpException(401, $this->gT('User data is missing required attributes:') . $sub_key_modified);
                                }
                                $tempValue = $tempValue[$segment];
                            }
                            $value = $tempValue;
                        } else {
                            $value = $this->getFromResourceData($sub_key_modified);
                        }
                        
                        $modifier = $sub_key_as_table[1];
                        if ($modifier === 'first_letter') {
                            $value = join('', array_map(
                                function ($spaceSeparatedElements) {
                                    return strtolower($spaceSeparatedElements[0]);
                                },
                                explode(' ', $value)
                            ));
                        } elseif ($modifier === 'capitalize') {
                            $value = ucfirst(strtolower($value));
                        } elseif ($modifier === 'upper_case') {
                            $value = strtoupper($value);
                        } elseif ($modifier === 'lower_case') {
                            $value = strtolower($value);
                        }
                    } else {
                        // Handle nested paths with | for better access to nested JSON
                        if (str_contains($sub_key, '|')) {
                            $segments = explode('|', $sub_key);
                            $tempValue = $this->resourceData;
                            foreach ($segments as $segment) {
                                if (!isset($tempValue[$segment])) {
                                    throw new CHttpException(401, $this->gT('User data is missing required attributes:') . $sub_key);
                                }
                                $tempValue = $tempValue[$segment];
                            }
                            $value = $tempValue;
                        } else {
                            $value = $this->getFromResourceData($sub_key);
                        }
                    }
                    
                    // Ensure we return a string value
                    if (is_array($value)) {
                        throw new CHttpException(401, $this->gT('Expected string value but got array for key:') . $sub_key);
                    }
                    
                    return $value;
                },
                explode("+", $iKey)
            );

            $rValue = join($iSeparator, $sub_values);
        } else {
            // Handle nested paths with | for direct keys
            if (str_contains($iKey, '|')) {
                $segments = explode('|', $iKey);
                $tempValue = $this->resourceData;
                foreach ($segments as $segment) {
                    if (!isset($tempValue[$segment])) {
                        throw new CHttpException(401, $this->gT('User data is missing required attributes:') . $iKey);
                    }
                    $tempValue = $tempValue[$segment];
                }
                $rValue = $tempValue;
                
                // Ensure we return a string
                if (is_array($rValue)) {
                    throw new CHttpException(401, $this->gT('Expected string value but got array for key:') . $iKey);
                }
            } else {
                $rValue = $this->getFromResourceData($iKey);
            }
        }
        return $rValue;
    }

    /**
     * @param string $key
     * @return mixed
     */
    private function getFromResourceData(string $key): mixed
    {
        $value = '';
        if (empty($this->resourceData[$key])) {
            throw new CHttpException(401, $this->gT('User data is missing required attributes to create new user:') . $key);
        } else {
            $value = $this->resourceData[$key];
        }
        return $value;
    }

    /**
     * get settings according to current DB and fixed config.php
     * @param string $setting
     * @param mixed $default
     * @return mixed
     */
    private function getGlobalSetting($setting, $default = null)
    {
        $AuthOAuth2Settings = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Settings['fixed'][$setting])) {
            return $AuthOAuth2Settings['fixed'][$setting];
        }
        if (isset($AuthOAuth2Settings[$setting])) {
            return $this->get($setting, null, null, $AuthOAuth2Settings[$setting]);
        }
        return $this->get($setting, null, null, $default);
    }

    /**
     * Get the fixed settings name
     * @return string[]
     */
    private function getFixedGlobalSetting()
    {
        $AuthOAuth2Setting = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Setting['fixed'])) {
            return array_keys($AuthOAuth2Setting['fixed']);
        }
        return [];
    }

    /**
     * Get the hidden settings name
     * @return string[]
     */
    private function getHiddenGlobalSetting()
    {
        $AuthOAuth2Setting = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Setting['hidden'])) {
            return $AuthOAuth2Setting['hidden'];
        }
        return [];
    }

     /**
      * Return global default permission
      * @return string
      */
    private static function getDefaultPermission()
    {
        return json_encode([
            'surveys' => [
                'create' => true,
                'read' => false,
                'update' => false,
                'delete' => false,
                'export' => false,
            ],
            'surveysgroups' => [
                'create' => false,
                'read' => true,
                'update' => false,
                'delete' => false,
            ],
            'labelsets' => [
                'create' => false,
                'read' => true,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
            ],
            'templates' => [
                'create' => false,
                'read' => true,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
            ],
            'users' => [
                'create' => false,
                'read' => false,
                'update' => false,
                'delete' => false,
            ],
            'usergroups' => [
                'create' => false,
                'read' => false,
                'update' => false,
                'delete' => false,
            ],
            'settings' => [
                'read' => false,
                'update' => false,
                'import' => false,
            ],
            'participantpanel' => [
                'create' => false,
                'read' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
            ],
            'auth_db' => [
                'read' => false,
            ]
        ]);
    }

    /**
     * Set the roles using current settings
     * @param integer $userId
     */
    private function setRolesToUser($userId)
    {
        $rolesKey = $this->getGlobalSetting('roles_key', '');
        if (!empty($rolesKey)) {
            $aRoles = $this->getNestedArrayData($rolesKey);
            if (!empty($aRoles)) {
                $resetPermission = false;
                $aRoles = (array) $aRoles;
                foreach ($aRoles as $role) {
                    $rolesRemovetext = $this->getGlobalSetting('roles_removetext', '');
                    $role = str_replace($rolesRemovetext, '', $role);
                    $criteria = new CDbCriteria();
                    if ($this->getGlobalSetting('roles_insensitive', false)) {
                        $criteria->compare('LOWER(name)', strtolower($role), true);
                    } else {
                        $criteria->compare('name', $role, true);
                    }
                    $oRole = Permissiontemplates::model()->find($criteria);
                    if ($oRole) {
                        $resetPermission = true;
                        Permissiontemplates::model()->applyToUser($userId, $oRole->ptid);
                    }
                }
                // Set the auth_oauth global permission to 0 (not used if have roles, but keep it at 0 for roles_needed
                if ($resetPermission) {
                    self::setOauthPermission($userId, false);
                }
            }
        }
    }
    /**
     * Set Oauth permission  : use to create permission with 0 ar read_p or update if exist.
     * @param integer $userId
     * @param boolean $read permission
     */
    private static function setOauthPermission($userId, $allow = true)
    {
        $oPermission = Permission::model()->find(
            "uid= :uid AND entity = :entity AND permission = :permission",
            array(
                'uid' => $userId,
                'entity' => 'global',
                'permission' => 'auth_oauth',
            )
        );
        if (!$oPermission) {
            $oPermission = new Permission();
            $oPermission->uid = $userId;
            $oPermission->entity = 'global';
            $oPermission->entity_id = 0;
            $oPermission->permission = 'auth_oauth';
        }
        $oPermission->create_p = 0;
        $oPermission->read_p = intval(boolval($allow));
        $oPermission->update_p = 0;
        $oPermission->delete_p = 0;
        $oPermission->import_p = 0;
        $oPermission->export_p = 0;
        $oPermission->save();
    }

    /**
     * Get a value from resource data with support for nested paths using | separator
     * This is used specifically for arrays like roles/groups
     * @param string $key Key with optional | for nested paths
     * @return array
     */
    private function getNestedArrayData(string $key): array
    {
        if (str_contains($key, '|')) {
            // Handle nested structure using | separator
            $segments = explode('|', $key);
            $value = $this->resourceData;
            
            foreach ($segments as $segment) {
                if (!isset($value[$segment])) {
                    return []; // Return empty array if path not found
                }
                $value = $value[$segment];
            }
            
            return (array)$value; // Cast to array to handle both array and single values
        }
        
        // If not a nested path, use standard method and convert to array
        $value = $this->getFromResourceData($key);
        return is_array($value) ? $value : [$value];
    }
}
