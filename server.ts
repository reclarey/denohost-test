import { runTracker } from './server/in_memory_tracker.ts'

const port = Deno.args[0];

runTracker({
  http: {
    port: port ? parseInt(port) : undefined,
  },
});
