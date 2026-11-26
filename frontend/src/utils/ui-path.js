// Auth callbacks are backend API routes; /login is the supported frontend entry.
export function normalizeUiPath(location = window.location, history = window.history) {
    if (location.pathname === '/' || location.pathname === '/login' || /^\/(api|appearance|assets|locales|metrics|ws|apm)(\/|$)/.test(location.pathname) || ['/favicon.svg', '/site-config.json'].includes(location.pathname) || /\.(?:js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map)$/i.test(location.pathname)) return false;
    history.replaceState(history.state, '', '/' + location.search + location.hash);
    return true;
}
