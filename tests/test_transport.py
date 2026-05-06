import asyncio

from sifr.messages import create_message
from sifr.transport import LocalTransport


def test_local_transport_sends_receives_messages():
    async def flow():
        a, b = LocalTransport.pair()
        msg = create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 1})
        await a.send(msg)
        got = await b.recv()
        assert got == msg
    asyncio.run(flow())
