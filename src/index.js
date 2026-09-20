export default {
  async fetch(request, env) {
    try {
      const result = await env.users_db
        .prepare('SELECT name FROM sqlite_master WHERE type=? ORDER BY name')
        .bind('table')
        .all();
      const tables = result.results.map(t => t.name).join(', ');
      return new Response(
        '✅ D1 connected!\n\nTables: ' + tables,
        { headers: { 'content-type': 'text/plain;charset=UTF-8' } }
      );
    } catch (e) {
      return new Response(
        '❌ Error: ' + e.message,
        { status: 500, headers: { 'content-type': 'text/plain;charset=UTF-8' } }
      );
    }
  }
};
