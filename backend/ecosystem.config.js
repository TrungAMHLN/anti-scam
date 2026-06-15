module.exports = {
  apps: [
    {
      name: 'AntiScam_v1',
      exec_mode: 'cluster',
      instances: 'max', // Or a number of instances,
      instance_var: 'INSTANCE_ID',
      script: './index.js',
      args: 'start',
        env: {
           "PORT": 3636,
            "NODE_ENV": "production"
        }
    }
  ]
}
