public override void Configure(Container container)
{
	Logger.Information("Entering AppHost.Configure()");
	
	var redisCfgServer = AppSettings.Get<string>("RedisCfgServers");
	var pwdRedisConfig = AppSettings.Get<string>("RedisConfigPwd");
	var redisCfgDbPort = AppSettings.Get<string>("RedisCfgPort");
	
	#region System configuration and Redis database connection pools
	
	if (redisCfgServer.Contains(':')) // we have a replica set
	{
		Logger.Debug($"The Redis Configuration DB is a ReplicaSet, need to register Redis Sentinels....");
		var replSetName = AppSettings.Get<string>("RedisCfgDbReplicaSetName");
		var redisConfigServerArray = redisCfgServer.Split(':', StringSplitOptions.RemoveEmptyEntries);
		for (var i = 0; i < redisConfigServerArray.Length; i++)
		{
			var server = redisConfigServerArray[i];
			server = $"{server}:2{redisCfgDbPort}"; //sentinel ports are by default Redis port + 20000
			redisConfigServerArray[i] = server;
		}

		var sentinelHosts = redisConfigServerArray;
		Logger.Debug($"Sentinel hosts: {sentinelHosts.ToJson()}, Redis Cfg Server ReplicaSet name: {replSetName}");
		try
		{
			var sentinel = new RedisSentinel(sentinelHosts, masterName: replSetName)
			{
				OnFailover = manager => 
				{
					Logger.Debug($"ONFAILOVER event received from {replSetName} ...");
					Logger.Debug($"RedisStats: '{RedisStats.ToDictionary().Dump()}'");
				},
				OnWorkerError = ex =>
				{
					Logger.Debug($"ONWORKERERROR event received from {replSetName}. Error: {ex.GetAllExceptions()}");
					Logger.Debug($"RedisStats: '{RedisStats.ToDictionary().Dump()}'");
				},
				OnSentinelMessageReceived = (channel, msg) =>
				{
					Logger.Debug($"ONSENTINELMESSAGERECEIVED event received from {replSetName}. Message: '{msg}' " +
								 $"Channel '{channel}'...");
					Logger.Debug($"RedisStats: '{RedisStats.ToDictionary().Dump()}'");
				}, 
			};
			sentinel.HostFilter = host => $"{host}?Db={BbConsumerConstants.RedisProdDb}&RetryTimeout=5000" +
										  $"&password={HttpUtility.UrlEncode(pwdRedisConfig)}";
			sentinel.RefreshSentinelHostsAfter = TimeSpan.FromSeconds(60);
			IRedisClientsManager redisManager = sentinel.Start();
			Logger.Debug($"RedisStats after sentinel.Start(): '{RedisStats.ToDictionary().Dump()}'");
			container.Register(c => new SysConfigRepository(redisManager));
		}
		catch (Exception e)
		{
			Logger.Error($"Failed to create, start and register the Redis config database Sentinel server. Error: {e.GetAllExceptions()}");
			throw;
		}
	}
	else // standalone setup
	{
		var connStrCfg = $"redis://{redisCfgServer}:{redisCfgDbPort}?ConnectTimeout=5000" +
						 $"&Db={BbConsumerConstants.RedisProdDb}&password={HttpUtility.UrlEncode(pwdRedisConfig)}";
	
		Logger.Debug($"Redis config: {connStrCfg}");
		var redisCfgPool = new PooledRedisClientManager(connStrCfg);
		container.Register(c => new SysConfigRepository(redisCfgPool));
	}
   
	var myServiceConfig = SetInitialBizBusLicenseServerConfiguration(AppSettings);        
	container.Register(Program.LogLevelSwitch);
	var assemblyVersion = typeof(Startup).Assembly.GetName().Version.ToString();
	container.Register(new GlobalData(myServiceConfig, assemblyVersion)); // global thread safe dataclass
	var globals = TryResolve<GlobalData>();
	globals.PersistMyServiceConfig();
	var myConfiguration = globals.MyServiceConfig.ServerConfiguration;

	if (myConfiguration.IsAdminDbReplicated())
	{
		Logger.Debug($"The Redis Admin DB is a ReplicaSet, need to register Redis Sentinels....");
		var redisAdminServer = AppSettings.Get<string>("RedisAdminServers");
		var pwdRedisAdmin = AppSettings.Get<string>("RedisAdminPwd");
		var redisAdminDbPort = AppSettings.Get<string>("RedisAdminPort");
		var replSetName = AppSettings.Get<string>("RedisAdminDbReplicaSetName");
		var redisAdminServerArray = redisAdminServer.Split(':', StringSplitOptions.RemoveEmptyEntries);
		for (var i = 0; i < redisAdminServerArray.Length; i++)
		{
			var server = redisAdminServerArray[i];
			server = $"{server}:2{redisAdminDbPort}"; //sentinel ports are by default Redis port + 20000
			redisAdminServerArray[i] = server;
		}

		var sentinelHosts = redisAdminServerArray;
		Logger.Debug($"Sentinel admin DB hosts: {sentinelHosts.ToJson()}, Redis admin server ReplicaSet name: {replSetName}");
		var sentinel = new RedisSentinel(sentinelHosts, masterName: replSetName)
		{
			OnFailover = manager => 
			{
				Logger.Debug($"ONFAILOVER event received from {replSetName} ...");
				Logger.Debug($"RedisStats: '{RedisStats.ToDictionary().Dump()}'");
			},
			OnWorkerError = ex =>
			{
				Logger.Debug($"ONWORKERERROR event received from {replSetName}. Error: {ex.GetAllExceptions()}");
				Logger.Debug($"RedisStats: '{RedisStats.ToDictionary().Dump()}'");
			},
			OnSentinelMessageReceived = (channel, msg) =>
			{
				Logger.Debug($"ONSENTINELMESSAGERECEIVED event received from {replSetName}. Message: '{msg}' " +
							 $"Channel '{channel}'...");
				Logger.Debug($"RedisStats: '{RedisStats.ToDictionary().Dump()}'");
			}, 
		};
		sentinel.HostFilter = host => $"{host}?Db={BbConsumerConstants.RedisProdDb}&RetryTimeout=5000" +
									  $"&password={HttpUtility.UrlEncode(pwdRedisAdmin)}";
		sentinel.RefreshSentinelHostsAfter = TimeSpan.FromSeconds(60);
		IRedisClientsManager redisManager = sentinel.Start();
		Logger.Debug($"RedisStats after sentinel.Start(): '{RedisStats.ToDictionary().Dump()}'");
		container.Register(c => new LsUserRepository(redisManager));
		container.Register<IRedisClientsManager>(c => redisManager);
		container.Register<IAuthRepository>(c => new RedisAuthRepository(redisManager));
	}
	else // standalone setup
	{
		Logger.Debug($"Redis admin conn string: '{myConfiguration.GetRedisAdminConnString()}'");
		var redisBbLicAdminPool = new PooledRedisClientManager(myConfiguration.GetRedisAdminConnString());
		container.Register(c => new LsUserRepository(redisBbLicAdminPool));
		container.Register<IRedisClientsManager>(c => redisBbLicAdminPool);
		container.Register<IAuthRepository>(c => new RedisAuthRepository(redisBbLicAdminPool));
	}
	
	Logger.Debug($"MongoDB connection string: '{myConfiguration.GetDbServerConnectString()}'");
	container.Register(c => new MongoClient(myConfiguration.GetDbServerConnectString()));

	Logger.Debug("Registering MongoDB repositories with IOC...");
	RegisterMongoDbRepos(container);
	Logger.Debug("Initializing license server DB...");
	InitMongoDb();

	#endregion

	#region Plugin registrations

	Plugins.Add(new ValidationFeature());
	Plugins.Add(new SwaggerFeature());
	Plugins.Add(new AuthFeature(() => new AuthUserSession(),
		new IAuthProvider[]
		{
			//ATTN: Logout is only called for the FIRST AuthProvider!!
			new LsAuthProvider(),
			new ApiKeyAuthProvider(AppSettings)
			{
				KeyTypes = new[] {"secret"},
				RequireSecureConnection = false,
			},
		}
	)
	{
		// the following regex requires minimum 7 max 53 characters and allows numbers and characters and all diacritics!
		ValidUserNameRegEx = new Regex(@"^(?=.{7,53}$)([\p{L}\w][.!_-]?)*$", RegexOptions.Compiled),
	});
	Plugins.Add(new ServerEventsFeature
	{
		HeartbeatInterval = TimeSpan.FromSeconds(8),
		IdleTimeout = TimeSpan.FromSeconds(30),
		OnConnect = (subscription, dict) =>
		{
			Logger.Information($"ONCONNECT EVENT: Subscription: {subscription.UserName} | Authenticated: {subscription.IsAuthenticated}");
		},
		OnCreated = (subscription, request) =>
		{
			var session = request.GetSession();
			Logger.Information($"ONCREATED EVENT: SessionProps: UserAuthID: '{session.UserAuthId}' | UserAuthName: '{session.UserAuthName}' | " +
					 $"UserName: '{session.UserName}' | SessionId: '{session.Id}' | AuthProvider: '{session.AuthProvider}' | IsAuthenticated: '{session.IsAuthenticated}' | " +
					 $"Request: '{request}' | Subscription: '{subscription.UserName}'");
		},
/*
		OnPublish = (subscription, response, data) =>
		{
			Logger.Information($"PUBLISH EVENT occured ..."); // This receives also HEARTBEATS!!
			// TODO: for testing only, remove when thesting is finished
			using (var service = HostContext.Resolve<ServerEventsSubscribersService>())
			{
				Logger.Information("SUBSCRIPTION STATS:");
				var subscriptionInfos = service.ServerEvents.GetAllSubscriptionInfos();
				if (subscriptionInfos.Count == 0) Logger.Information("There are currently NO subscriptions registered!");
				else
				{
					Logger.Information($"There are currently {subscriptionInfos.Count} registered subscriptions.");
					foreach (var subscriptionInfo in subscriptionInfos)
					{
						Logger.Information($"subscription: {subscriptionInfo.SubscriptionId} | {subscriptionInfo.UserName}");
					}
				}
			}
			Logger.Information($"Subscription: {subscription} | Response: {response} | Data: {data} | Size of data: {data.Length} chars.");
		},
*/
		OnSubscribe = (subscription) =>
		{
			Logger.Information($"SUBSCRIBE EVENT: new subscription for user: DisplayName: {subscription.DisplayName} | UserID: {subscription.UserId} | " +
					 $"UserName: {subscription.UserName} | SessionID: {subscription.SessionId} | SubscriptionId: {subscription.SubscriptionId} | " +
					 $"IsAuthenticated: {subscription.IsAuthenticated} | IsClosed: {subscription.IsClosed}");

			// for testing only:
			using (var service = HostContext.Resolve<ServerEventsSubscribersService>())
			{
				Logger.Information("SUBSCRIPTION STATS:");
				var subscriptionInfos = service.ServerEvents.GetAllSubscriptionInfos();
				if (subscriptionInfos.Count == 0) Logger.Information("There are currently NO subscriptions registered!");
				else
				{
					Logger.Information($"There are currently {subscriptionInfos.Count} registered subscriptions.");
					foreach (var subscriptionInfo in subscriptionInfos)
					{
						Logger.Information($"subscription: {subscriptionInfo.SubscriptionId} | {subscriptionInfo.UserName}");
					}
				}
			}
		},
		OnUnsubscribe = (subscription) =>
		{
			Logger.Information($"UNSUBSCRIBE EVENT: unsubscribed user: {subscription.DisplayName} | UserID: {subscription.UserId} | " +
					 $"UserName: {subscription.UserName} | SessionID: {subscription.SessionId} | SubscriptionId: {subscription.SubscriptionId} | " +
					 $"IsAuthenticated: {subscription.IsAuthenticated} | IsClosed: {subscription.IsClosed}");
			// for testing only:
			using (var service = HostContext.Resolve<ServerEventsSubscribersService>())
			{
				Logger.Information("SUBSCRIPTION STATS:");
				var subscriptionInfos = service.ServerEvents.GetAllSubscriptionInfos();
				if (subscriptionInfos.Count == 0) Logger.Information("There are currently NO subscriptions registered!");
				else
				{
					Logger.Information($"There are currently {subscriptionInfos.Count} registered subscriptions.");
					foreach (var subscriptionInfo in subscriptionInfos)
					{
						Logger.Information($"subscription: {subscriptionInfo.SubscriptionId} | {subscriptionInfo.UserName}");
					}
				}
			}
		}
	});
/*
	var nativeTypes = this.GetPlugin<NativeTypesFeature>();
	nativeTypes.MetadataTypesConfig.AddNamespaces = new[] {
		"BizBusLicenseServer.ServiceModel.Util",
		"BizBusLicenseServer.ServiceModel",
	}.ToList();
*/
	var quartzFeature = BuildQuartzJobs();
	Plugins.Add(quartzFeature);

	// CORS Feature plugin depending on Runtime
	Enum.TryParse(AppSettings.Get<string>("Runtime"), out Runtime runtime);
	switch (runtime)
	{
		case Runtime.BediDevelDockerAppServer:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.BediDevelDockerLocal:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.BediDevelLocal:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.BediDevelRs:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.LfDevelDatacenter:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.LfDemoDatacenter:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.IntusTestDatacenter:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.LfProdDatacenter:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
		case Runtime.IntusDevelDocker:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is ENABLED.");
			Plugins.Add(new CorsFeature( allowCredentials: true ));
			PreRequestFilters.Add((request, response) =>
			{
				var corsFeature = HostContext.GetPlugin<CorsFeature>();
				var origin = request.Headers.Get(HttpHeaders.Origin);
				if (corsFeature != null && origin != null)
				{
					//nicht für die Produktion! Das entspricht quasi Access-Control-Allow-Origin: *
					response.AddHeader(HttpHeaders.AllowOrigin, origin);
				}
			});			        
			
			break;
		default:
			Logger.Information($"The runtime environment is '{runtime.ToString()}', the CORS feature is DISABLED.");
			break;
	}

	#endregion

	#region Registration of several providers

	var cachingProvider = myConfiguration.CacheProvider;
	if (cachingProvider.CompareIgnoreCase("Memory") == 0)
	{
		container.Register<ICacheClient>(new MemoryCacheClient());
	}
	else if (cachingProvider.CompareIgnoreCase("Redis") == 0)
	{
		//container.Register(c => redisCachePool.GetCacheClient());
		if (myConfiguration.IsCacheDbReplicated())
		{
			Logger.Debug($"The Redis Cache DB is a ReplicaSet, need to register Redis Sentinels....");
			var redisCacheServer = AppSettings.Get<string>("RedisCacheServers");
			var pwdRedisCache = AppSettings.Get<string>("RedisCachePwd");
			var redisCacheDbPort = AppSettings.Get<string>("RedisCachePort");
			var replSetName = AppSettings.Get<string>("RedisCacheDbReplicaSetName");
			var redisCacheServerArray = redisCacheServer.Split(':', StringSplitOptions.RemoveEmptyEntries);
			for (var i = 0; i < redisCacheServerArray.Length; i++)
			{
				var server = redisCacheServerArray[i];
				server = $"{server}:2{redisCacheDbPort}"; //sentinel ports are by default Redis port + 20000
				redisCacheServerArray[i] = server;
			}

			var sentinelHosts = redisCacheServerArray;
			Logger.Debug($"Sentinel cache DB hosts: {sentinelHosts.ToJson()}, Redis cache server ReplicaSet name: {replSetName}");
			var sentinel = new RedisSentinel(sentinelHosts, masterName: replSetName)
			{
				OnFailover = manager => 
				{
					Logger.Debug($"ONFAILOVER event received from {replSetName} ...");
				},
				OnWorkerError = ex =>
				{
					Logger.Debug($"ONWORKERERROR event received from {replSetName}. Error: {ex.GetAllExceptions()}");
				},
				OnSentinelMessageReceived = (channel, msg) =>
				{
					Logger.Debug($"ONSENTINELMESSAGERECEIVED event received from {replSetName}. Message: '{msg}' " +
								 $"Channel '{channel}'...");
				}, 
			};
			sentinel.HostFilter = host => $"{host}?Db={BbConsumerConstants.RedisProdDb}&RetryTimeout=5000" +
										  $"&password={HttpUtility.UrlEncode(pwdRedisCache)}";
			sentinel.RefreshSentinelHostsAfter = TimeSpan.FromSeconds(60);
			IRedisClientsManager redisManager = sentinel.Start();
			Logger.Debug($"RedisStats after sentinel.Start(): '{RedisStats.ToDictionary().Dump()}'");
			container.Register(c => redisManager.GetCacheClient());
		}
		else
		{
			var redisCachePool = new PooledRedisClientManager(myConfiguration.GetRedisCacheConnString());
			container.Register(c => redisCachePool.GetCacheClient());
		}
	   
	}

	#endregion

	#region ServiceStack Filters

	//sliding authentication
	GlobalResponseFilters.Add((httpReq, httpRes, dto) =>
	{
		var session = httpReq.GetSession();
		if (!session.IsAuthenticated) return;
		
		var sessionKey = SessionFeature.GetSessionKey(session.Id);
		var ttl = httpReq.GetCacheClient().GetTimeToLive(sessionKey);

		Logger.Debug($"Session with Id {session.Id} will expire in '{ttl.ToString()}'. Extending it so it will last for another " +
					 $"'{CommonConstants.SessionExpiryInMinutes}' minutes.");
			
		httpReq.SaveSession(session, TimeSpan.FromMinutes(CommonConstants.SessionExpiryInMinutes));
	});

	#endregion

	#region RabbitMQ bus IOC registration

	//Register to use a Rabbit MQ Server
	Logger.Information($"Registering RabbitMQ server using the EasyNetQ library....");
	var rabbitVHost = "bbls";

	try
	{
		var rabbitConnectString = myConfiguration.GetRabbitMqConnectString(rabbitVHost);
		var msgBus = RabbitHutch.CreateBus(rabbitConnectString);
		if (!msgBus.IsConnected)
		{
			var errMsg =
				$"Error connecting to RabbitMQ at startup with connectionString {myConfiguration.GetRabbitMqConnectString(rabbitVHost)}.";
			Logger.Error(errMsg);
			throw new BizBusException(errMsg);
		}
		Logger.Information("Successfully connected to RabbitMQ server.");
		container.Register(msgBus);
	}
	catch (Exception ex)
	{
		Logger.Error($"Error connecting to RabbitMQ with connectionString {myConfiguration.GetRabbitMqConnectString(rabbitVHost)}. Error: {ex}");
		throw;
	}

	#endregion
	
	#region General IOC container registrations

	Logger.Debug("Register general objects with IOC container....");
	container.Register(c => new BbRequestMetaData()).ReusedWithin(ReuseScope.Request);
	container.RegisterAs<TrackAuthEvents, IAuthEvents>();

	#endregion

	#region Exception handling

	ServiceExceptionHandlers.Add((httpReq, request, exception) => {
		var msg = string.Empty;
		var requestType = request.GetType();
		var exType = exception.GetType();
		if (exType == typeof(HttpError))
		{
			var stackEx = (HttpError) exception;
			var status = stackEx.Status;
			if (status == 403)
			{
				var op = Metadata.GetOperation(requestType);
				var reqRoles = string.Empty;
				if (op.RequiredRoles.Count > 0)
				{
					var count = 0;
					foreach (var role in op.RequiredRoles)
					{
						if (count > 0) reqRoles += " | ";
						reqRoles += role;
						count++;
					}
				}

				if (op.RequiresAnyRole.Count > 0)
				{
					foreach (var role in op.RequiresAnyRole)
					{
						if (!reqRoles.IsNullOrEmpty()) reqRoles += " | ";
						reqRoles += role;
					}
				}

				var reqPerm = string.Empty;
				if (op.RequiredPermissions.Count > 0)
				{
					var count = 0;
					foreach (var perm in op.RequiredPermissions)
					{
						if (count > 0) reqPerm += " | ";
						reqPerm += perm;
						count++;
					}
				}

				if (op.RequiresAnyPermission.Count > 0)
				{
					foreach (var permission in op.RequiresAnyPermission)
					{
						if (!reqPerm.IsNullOrEmpty()) reqRoles += " | ";
						reqPerm += permission;
					}
				}
				
				msg = $"Service Exception for request '{request.ToJson()}'. | Operation: '{httpReq.OperationName}' | " +
					  $"Calling user: '{httpReq.GetSession().UserName}' | Calling IP: '{httpReq.RemoteIp}' | Exception: '{exception.ToJson()}' | " +
					  $"This operation requires membership in one of the following roles: '{reqRoles}' and one of the following permissions: '{reqPerm}'";
				Logger.Error(msg);
				return null;
			}
		}
		
		msg = $"Service Exception for request '{request.ToJson()}'. | Operation: '{httpReq.OperationName}' | " +
			  $"Calling user: '{httpReq.GetSession().UserName}' | Calling IP: '{httpReq.RemoteIp}' | Error: '{exception.ToJson()}'";

		Logger.Error(msg);
		return null; //continue with default Error Handling
	});

	//Handle Unhandled Exceptions occurring outside of Services
	//E.g. Exceptions during Request binding or in filters:
	this.UncaughtExceptionHandlers.Add((req, res, operationName, ex) => {
		res.WriteAsync($"Error: {ex.GetType().Name}: {ex.Message}");
		res.EndRequest(skipHeaders: true);
	});
	

	#endregion	        

	AfterInitCallbacks.Add(host =>
	{
		var configRepo = TryResolve<SysConfigRepository>();
		if (!DoesUserExist("bizbuslicenseadmin"))
			CreateLsAdminUser();
		if (!DoesUserExist(BbConsumerConstants.LfAccount))
		{
			var roles = new string[] {"SysOps"};
			var apiKey = CreateSystemAccount(BbConsumerConstants.LfAccount, "Linuxfabrik SysOp account", roles);
			configRepo.SetConfigurationItem(new SysConfigItem("cfg:keys", BbConsumerConstants.LfAccount, apiKey));
		}
		InitLicenseServer();
		//RegisterScheduledJobs(container);
		RegisterMsgSubscriptions();
	});

}
