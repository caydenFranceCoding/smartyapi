// Primary Ohio address suggestions endpoint
app.get('/api/ohio-address-suggestions', async (req, res) => {
  try {
    const { query, limit = 5 } = req.query;

    // FIXED: Changed minimum from 4 to 2 characters to match frontend config
    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Invalid query parameter',
        message: 'Query parameter is required and must be at least 2 characters long',
        code: 'INVALID_QUERY'
      });
    }

    const normalizedQuery = query.trim();
    const resultLimit = Math.min(Math.max(parseInt(limit) || 5, 1), 10);
    const cacheKey = `ohio:${normalizedQuery.toLowerCase()}:${resultLimit}`;

    // Check cache first
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return res.json({
        success: true,
        suggestions: cached,
        metadata: {
          source: 'cache',
          query: normalizedQuery,
          count: cached.length,
          cached: true
        }
      });
    }

    console.log(`Address search initiated: "${normalizedQuery}"`);

    // Try SmartyStreets first for maximum accuracy
    if (process.env.SMARTYSTREETS_AUTH_ID && process.env.SMARTYSTREETS_AUTH_TOKEN) {
      try {
        console.log('Attempting SmartyStreets lookup...');

        const smartyResponse = await axios.get('https://us-street.api.smartystreets.com/street-address', {
          params: {
            'auth-id': process.env.SMARTYSTREETS_AUTH_ID,
            'auth-token': process.env.SMARTYSTREETS_AUTH_TOKEN,
            street: normalizedQuery,
            state: 'OH',
            candidates: resultLimit
          },
          timeout: 8000,
          headers: {
            'User-Agent': 'OhioEnergyAPI/1.0'
          }
        });

        console.log(`SmartyStreets returned ${smartyResponse.data.length} results`);

        if (smartyResponse.data.length > 0) {
          const smartySuggestions = smartyResponse.data
            .filter(addr => addr.components?.state_abbreviation === 'OH')
            .map(formatSmartyStreetsAddress)
            .slice(0, resultLimit);

          setCachedResult(cacheKey, smartySuggestions);

          return res.json({
            success: true,
            suggestions: smartySuggestions,
            metadata: {
              source: 'smartystreets',
              provider: 'SmartyStreets',
              query: normalizedQuery,
              count: smartySuggestions.length,
              verified: true,
              cached: false
            }
          });
        }

      } catch (smartyError) {
        console.error('SmartyStreets error:', {
          status: smartyError.response?.status,
          message: smartyError.message,
          code: smartyError.code
        });

        // Continue to fallback rather than failing completely
        console.log('Falling back to Nominatim geocoding service...');
      }
    } else {
      console.log('SmartyStreets not configured, using Nominatim...');
    }

    // Fallback to Nominatim for broader coverage
    console.log('Using Nominatim fallback service...');

    const nominatimResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: `${normalizedQuery}, Ohio, USA`,
        format: 'json',
        addressdetails: 1,
        limit: resultLimit,
        countrycodes: 'us',
        'accept-language': 'en'
      },
      headers: {
        'User-Agent': 'OhioEnergyAPI/1.0'
      },
      timeout: 10000
    });

    console.log(`Nominatim returned ${nominatimResponse.data.length} raw results`);

    // Filter and format Ohio addresses
    const ohioSuggestions = nominatimResponse.data
      .filter(addr => {
        const state = addr.address?.state?.toLowerCase();
        return state && state.includes('ohio');
      })
      .map(formatNominatimAddress)
      .filter(suggestion => suggestion.address) // Filter out empty addresses
      .slice(0, resultLimit);

    setCachedResult(cacheKey, ohioSuggestions);

    console.log(`Processed ${ohioSuggestions.length} Ohio addresses`);

    res.json({
      success: true,
      suggestions: ohioSuggestions,
      metadata: {
        source: 'nominatim',
        provider: 'OpenStreetMap',
        query: normalizedQuery,
        count: ohioSuggestions.length,
        verified: false,
        cached: false
      }
    });

  } catch (error) {
    console.error('Address suggestion error:', {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      stack: error.stack
    });

    // Enhanced error handling
    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return res.status(504).json({
        success: false,
        error: 'Request timeout',
        message: 'The address search took too long. Please try with more specific details.',
        code: 'TIMEOUT_ERROR'
      });
    }

    if (error.response?.status === 429) {
      return res.status(429).json({
        success: false,
        error: 'Service rate limit exceeded',
        message: 'The geocoding service is temporarily unavailable. Please try again shortly.',
        code: 'SERVICE_RATE_LIMIT'
      });
    }

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Unable to process address search request',
      code: 'INTERNAL_ERROR',
      debug: process.env.NODE_ENV !== 'production' ? error.message : undefined
    });
  }
});
