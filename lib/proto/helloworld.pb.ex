defmodule Misc.Protos.HelloRequest do
  @moduledoc false

  use Protobuf, protoc_gen_elixir_version: "0.12.0", syntax: :proto3

  field(:name, 1, type: :string)
end

defmodule Misc.Protos.HelloReply do
  @moduledoc false

  use Protobuf, protoc_gen_elixir_version: "0.12.0", syntax: :proto3

  field(:message, 1, type: :string)
end

defmodule Misc.Protos.Greeter.Service do
  @moduledoc false

  use GRPC.Service, name: "Misc.Protos.Greeter", protoc_gen_elixir_version: "0.12.0"

  rpc(:SayHello, Misc.Protos.HelloRequest, Misc.Protos.HelloReply)

  rpc(:SayHelloStreamReply, Misc.Protos.HelloRequest, stream(Misc.Protos.HelloReply))

  rpc(:SayHelloBidiStream, stream(Misc.Protos.HelloRequest), stream(Misc.Protos.HelloReply))
end

defmodule Misc.Protos.Greeter.Stub do
  @moduledoc false

  use GRPC.Stub, service: Misc.Protos.Greeter.Service
end
