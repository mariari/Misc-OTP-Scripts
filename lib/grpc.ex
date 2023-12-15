defmodule Misc.GRPC do
end

defmodule Misc.GRPC.Hello.Server do
  use GRPC.Server, service: Misc.Protos.Greeter.Service

  alias Misc.Protos.{HelloReply, HelloRequest}
  alias GRPC.Server
  alias GRPC.Server.Stream, as: GStream

  @spec say_hello(HelloRequest.t(), GStream.t()) :: any()
  def say_hello(request, _stream) do
    HelloReply.new(message: "Hello #{request.name}")
  end

  @spec say_hello_stream_reply(HelloRequest.t(), GStream.t()) :: any()
  def say_hello_stream_reply(request, stream) do
    reply = HelloReply.new(message: "Hello #{request.name}")
    Server.send_reply(stream, reply, [])
  end

  @spec say_hello_bidi_stream(Enumerable.t(HelloRequest.t()), GStream.t()) :: any()
  def say_hello_bidi_stream(request, stream) do
    IO.inspect(request, label: "requests")

    request
    |> Enum.each(fn item ->
      reply = HelloReply.new(message: "Hello #{item.name}")
      Server.send_reply(stream, reply, [])
    end)

    IO.inspect(Enum.to_list(request) |> length(), label: "when this runs")
    stream
  end
end

defmodule Misc.GRPC.Hello.Endpoint do
  use GRPC.Endpoint

  intercept GRPC.Server.Interceptors.Logger
  run Misc.GRPC.Hello.Server
end

defmodule Misc.GRPC.Supervisor do
  use Supervisor

  def start_link(port) do
    Supervisor.start_link(__MODULE__, port, name: __MODULE__)
  end

  def init(port) do
    children = [
      {GRPC.Server.Supervisor, endpoint: Misc.GRPC.Hello.Endpoint, port: port, start_server: true}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

# Misc.GRPC.Supervisor.start_link(50051)
