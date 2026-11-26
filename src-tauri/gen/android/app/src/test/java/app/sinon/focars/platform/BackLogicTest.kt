package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Test

class BackLogicTest {
  @Test fun handledByUi() = assertEquals(BackLogic.Action.HANDLED, BackLogic.decide("\"ok\""))
  @Test fun rootMinimizes() = assertEquals(BackLogic.Action.MINIMIZE, BackLogic.decide("\"root\""))
  @Test fun timeoutStays() = assertEquals(BackLogic.Action.STAY, BackLogic.decide(null))
  @Test fun noJsStays() = assertEquals(BackLogic.Action.STAY, BackLogic.decide("\"nojs\""))
  @Test fun errorStays() = assertEquals(BackLogic.Action.STAY, BackLogic.decide("\"err\""))
  @Test fun nullJsStays() = assertEquals(BackLogic.Action.STAY, BackLogic.decide("null"))
}
