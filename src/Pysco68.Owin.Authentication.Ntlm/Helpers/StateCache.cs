namespace Pysco68.Owin.Authentication.Ntlm.Security
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Runtime.Caching;

    /// <summary>
    /// An in-memory cache for the login handshakes
    /// </summary>
    class StateCache
    {
        #region fields
        private MemoryCache Cache;

        /// <summary>
        /// Expiration time of a login attempt state in minutes,
        /// defaults to 2
        /// </summary>
        public int ExpirationTime { get; set; }
        #endregion

        /// <summary>
        /// Create a state cache
        /// </summary>
        /// <param name="name"></param>
        public StateCache(string name)
        {
            this.Cache = new MemoryCache(name);
            this.ExpirationTime = 2;            
        }

        /// <summary>
        /// Try to get a state by its key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        public bool TryGet(string key, out HandshakeState state)
        {
            if (Cache.Contains(key))
            {
                object tmp = Cache[key];
                if (tmp != null)
                {
                    state = (HandshakeState)tmp;
                    return true;
                }
            }

            state = default(HandshakeState);
            return false;
        }

        /// <summary>
        /// Add a new state to the cache
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        public void Add(string key, HandshakeState state)
        {
            this.Cache.Set(key, state, GetCacheItemPolicy(this.ExpirationTime));
        }

        /// <summary>
        /// Add a new state to the cache and set a custom cache item policy
        /// </summary>
        /// <param name="key"></param>
        /// <param name="state"></param>
        /// <param name="policy"></param>
        public void Add(string key, HandshakeState state, CacheItemPolicy policy)
        {
            this.Cache.Set(key, state, policy);
        }

        /// <summary>
        /// Remove a key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool TryRemove(string key)
        {
            return this.Cache.Remove(key) != null;
        }

        #region Helpers
        /// <summary>
        /// Gets a cache item policy.
        /// </summary>
        /// <param name="minutes">Absolute expiration time in x minutes</param>
        /// <returns></returns>
        private static CacheItemPolicy GetCacheItemPolicy(int minutes)
        {
            var policy = new CacheItemPolicy()
            {
                Priority = CacheItemPriority.Default,
                AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(minutes),
                RemovedCallback = (item) => 
                {  
                    // dispose cached item at removal
                    var asDisposable = item.CacheItem as IDisposable;
                    if (asDisposable != null)
                        asDisposable.Dispose();
                }
            };
            return policy;
        }
        #endregion

    }
}
