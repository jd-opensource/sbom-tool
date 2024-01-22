Pod::Spec.new do |spec|
  spec.name          = 'TestPod'
  spec.version       = '1.0.0'

  spec.homepage      = 'https://github.com/test/TestPod'
  spec.authors       = { 'Test' => 'test@example.com' }
  spec.license       = { :type => 'BSD' }
  spec.source        = { :git => 'https://https://github.com/test/TestPod.git', :tag => 'v1.1.0' }
  spec.summary       = 'TestPod Project.'

  spec.module_name   = 'Test'
  spec.swift_version = '4.0'
  spec.framework      = 'SystemConfiguration'
  spec.ios.framework  = 'UIKit'
  spec.osx.framework  = 'AppKit'

  spec.ios.deployment_target  = '9.0'
  spec.osx.deployment_target  = '10.10'

  spec.dependency 'SomeOtherPod'
  spec.dependency 'AFNetworking', '~> 1.0'
  spec.dependency 'AFNetworking', '~> 1.0', :configurations => ['Debug']
  spec.dependency 'AFNetworking', '~> 1.0', :configurations => :debug
  spec.dependency 'RestKit/CoreData', '~> 0.20.0'
  spec.dependency 'MBProgressHUD', '~> 0.5'
end