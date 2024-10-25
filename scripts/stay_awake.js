ObjC.schedule(ObjC.mainQueue, () => {
  try {
    ObjC.classes.UIApplication.sharedApplication().setIdleTimerDisabled_(ptr(1))
  } finally {

  }
})
