import WanRouter

WanRouter.init('testgw1-config.json')
WanRouter.start('ens192', 'https://localhost:51225/dl')